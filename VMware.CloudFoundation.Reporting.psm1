# Copyright 2022 VMware, Inc.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Note:
# This PowerShell module should be considered entirely experimental. It is still in development and not tested beyond lab
# scenarios. It is recommended you don't use it for any production environment without testing extensively!

# Allow communication with self-signed certificates when using Powershell Core. If you require all communications to be
# secure and do not wish to allow communication with self-signed certificates, remove lines 13-36 before importing the
# module.

if ($PSEdition -eq 'Core') {
    $PSDefaultParameterValues.Add("Invoke-RestMethod:SkipCertificateCheck", $true)
}

if ($PSEdition -eq 'Desktop') {
    # Allow communication with self-signed certificates when using Windows PowerShell
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;

    if ("TrustAllCertificatePolicy" -as [type]) {} else {
        Add-Type @"
	using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertificatePolicy : ICertificatePolicy {
        public TrustAllCertificatePolicy() {}
		public bool CheckValidationResult(
            ServicePoint sPoint, X509Certificate certificate,
            WebRequest wRequest, int certificateProblem) {
            return true;
        }
	}
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertificatePolicy
    }
}

#######################################################################################################################
#############################  C O M B I N E D   O P E R A T I O N S   F U N C T I O N S   ############################

Function Invoke-VcfHealthReport {
    <#
        .SYNOPSIS
        Perform health checks

        .DESCRIPTION
        The Invoke-VcfHealthReport provides a single cmdlet to perform health checks across a VMware Cloud Foundation instance.

        .EXAMPLE
        Invoke-VcfHealthReport -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser admin@local -sddcManagerPass VMw@re1!VMw@re1! -sddcManagerRootPass VMw@re1! -reportPath F:\Reporting -allDomains
        This example runs a health check across a VMware Cloud Foundation instance.

        .EXAMPLE
        Invoke-VcfHealthReport -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser admin@local -sddcManagerPass VMw@re1!VMw@re1! -sddcManagerRootPass VMw@re1! -reportPath F:\Reporting -workloadDomain sfo-w01
        This example runs a health check for a specific Workload Domain within a VMware Cloud Foundation instance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerFqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerUser,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerPass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerRootPass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$reportPath,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific--WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$darkMode
    )

    Try {
        Clear-Host; Write-Host ""

        Start-CreateReportDirectory -path $reportPath -sddcManagerFqdn $sddcManagerFqdn -reportType health # Setup Report Location and Report File
        if (!(Test-Path -Path $reportPath)) {Write-Warning "Unable to locate report path $reportPath, enter a valid path and try again"; Write-Host ""; Break }
        if ($message = Test-VcfHealthPrereq) {Write-Warning $message; Write-Host ""; Break }
        if ($PsBoundParameters.ContainsKey("allDomains")) {
            $workflowMessage = "VMware Cloud Foundation instance ($sddcManagerFqdn)"
        } else {
            $workflowMessage = "Workload Domain ($workloadDomain)"
        }
        Start-SetupLogFile -Path $reportPath -ScriptName $MyInvocation.MyCommand.Name # Setup Log Location and Log File
        Write-LogMessage -Type INFO -Message "Starting the process of creating a Health Report for $workflowMessage." -Colour Yellow
        Write-LogMessage -Type INFO -Message "Setting up the log file to path $logfile."
        Write-LogMessage -Type INFO -Message "Setting up report folder and report $reportName."

        Write-LogMessage -Type INFO -Message "Running an SoS Health Check for $workflowMessage, process takes time."
        if ($PsBoundParameters.ContainsKey("allDomains")) { 
            $jsonFilePath = Request-SoSHealthJson -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -rootPass $sddcManagerRootPass -reportPath $reportFolder -allDomains
        } elseif ($PsBoundParameters.ContainsKey("workloadDomain")) {
            $jsonFilePath = Request-SoSHealthJson -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -rootPass $sddcManagerRootPass -reportPath $reportFolder -workloadDomain $workloadDomain
        }

        # Generating all SoS Health Data
        Write-LogMessage -Type INFO -Message "Generating the Service Health Report using the SoS output for $workflowMessage."
        Write-LogMessage -Type INFO -Message "Generating the DNS Health Report using the SoS output for $workflowMessage."
        Write-LogMessage -Type INFO -Message "Generating the NTP Health Report using the SoS output for $workflowMessage."
        Write-LogMessage -Type INFO -Message "Generating the Certificate Health Report using the SoS output for $workflowMessage."
        Write-LogMessage -Type INFO -Message "Generating the ESXi Health Report using the SoS output for $workflowMessage."
        Write-LogMessage -Type INFO -Message "Generating the vSAN Health Report using the SoS output for $workflowMessage."
        Write-LogMessage -Type INFO -Message "Generating the vSAN Storage Policy Health Report using the SoS output for $workflowMessage."
        Write-LogMessage -Type INFO -Message "Generating the vCenter Server Health Report using the SoS output for $workflowMessage."
        if ($PsBoundParameters.ContainsKey("failureOnly")) {
            $serviceHtml = Publish-ServiceHealth -json $jsonFilePath -html -failureOnly
            $dnsHtml = Publish-DnsHealth -json $jsonFilePath -html -failureOnly
            $ntpHtml = Publish-NtpHealth -json $jsonFilePath -html -failureOnly
            $certificateHtml = Publish-CertificateHealth -json $jsonFilePath -html -failureOnly
            $esxiHtml = Publish-EsxiHealth -json $jsonFilePath -html -failureOnly
            $vsanHtml = Publish-VsanHealth -json $jsonFilePath -html -failureOnly
            $vsanPolicyHtml = Publish-VsanStoragePolicy -json $jsonFilePath -html -failureOnly
            $vcenterHtml = Publish-VcenterHealth -json $jsonFilePath -html -failureOnly
            $nsxtEdgeClusterHtml = Publish-NsxtEdgeClusterHealth -json $jsonFilePath -html -failureOnly
            $nsxtEdgeNodeHtml = Publish-NsxtEdgeNodeHealth -json $jsonFilePath -html -failureOnly
        } else {
            $serviceHtml = Publish-ServiceHealth -json $jsonFilePath -html
            $dnsHtml = Publish-DnsHealth -json $jsonFilePath -html
            $ntpHtml = Publish-NtpHealth -json $jsonFilePath -html
            $certificateHtml = Publish-CertificateHealth -json $jsonFilePath -html
            $esxiHtml = Publish-EsxiHealth -json $jsonFilePath -html
            $vsanHtml = Publish-VsanHealth -json $jsonFilePath -html
            $vsanPolicyHtml = Publish-VsanStoragePolicy -json $jsonFilePath -html
            $vcenterHtml = Publish-VcenterHealth -json $jsonFilePath -html
            $nsxtEdgeClusterHtml = Publish-NsxtEdgeClusterHealth -json $jsonFilePath -html
            $nsxtEdgeNodeHtml = Publish-NsxtEdgeNodeHealth -json $jsonFilePath -html
        }

        # Generating the NSX Manager Health Data Using SoS output and Supplimental PowerShell Request Functions
        Write-LogMessage -Type INFO -Message "Generating the NSX-T Data Center Health Report using the SoS output for $workflowMessage."
        if ($PsBoundParameters.ContainsKey("allDomains") -and $PsBoundParameters.ContainsKey("failureOnly")) {
            $nsxtHtml = Publish-NsxtCombinedHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -json $jsonFilePath -allDomains -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("allDomains")) {
            $nsxtHtml = Publish-NsxtCombinedHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -json $jsonFilePath -allDomains
        }
        if ($PsBoundParameters.ContainsKey("workloadDomain") -and $PsBoundParameters.ContainsKey("failureOnly")) {
            $nsxtHtml = Publish-NsxtCombinedHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -json $jsonFilePath -workloadDomain $workloadDomain -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("workloadDomain")) {
            $nsxtHtml = Publish-NsxtCombinedHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -json $jsonFilePath -workloadDomain $workloadDomain
        }

        # Generating the Connectivity Health Data Using SoS output and Supplimental PowerShell Request Functions
        Write-LogMessage -Type INFO -Message "Generating the Connectivity Health Report using the SoS output for $workflowMessage."
        if ($PsBoundParameters.ContainsKey("allDomains") -and $PsBoundParameters.ContainsKey("failureOnly")) { 
            $componentConnectivityHtml = Publish-ComponentConnectivityHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -json $jsonFilePath -allDomains -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("allDomains")) {
            $componentConnectivityHtml = Publish-ComponentConnectivityHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -json $jsonFilePath -allDomains
        }
        if ($PsBoundParameters.ContainsKey("workloadDomain") -and $PsBoundParameters.ContainsKey("failureOnly")) { 
            $componentConnectivityHtml = Publish-ComponentConnectivityHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -json $jsonFilePath -workloadDomain $workloadDomain -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("workloadDomain")) {
            $componentConnectivityHtml = Publish-ComponentConnectivityHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -json $jsonFilePath -workloadDomain $workloadDomain
        }

        # Generating the Backup Status Health Data Using PowerShell Request Functions
        Write-LogMessage -Type INFO -Message "Generating the Backup Status Report for $workflowMessage."
        if ($PsBoundParameters.ContainsKey("allDomains") -and $PsBoundParameters.ContainsKey("failureOnly")) { 
            $backupStatusHtml = Publish-BackupStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("allDomains")) {
            $backupStatusHtml = Publish-BackupStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains
        }
        if ($PsBoundParameters.ContainsKey("workloadDomain") -and $PsBoundParameters.ContainsKey("failureOnly")) {
            $backupStatusHtml = Publish-BackupStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("workloadDomain")) {
            $backupStatusHtml = Publish-BackupStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
        }
        
        # Generating the Snapshot Status Health Data Using PowerShell Request Functions
        Write-LogMessage -type INFO -Message "Generating the Snapshots Report for $workflowMessage."
        if ($PsBoundParameters.ContainsKey("allDomains") -and $PsBoundParameters.ContainsKey("failureOnly")) {
            $snapshotStatusHtml = Publish-SnapshotStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("allDomains")) {
            $snapshotStatusHtml = Publish-SnapshotStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains
        }
        if ($PsBoundParameters.ContainsKey("workloadDomain") -and $PsBoundParameters.ContainsKey("failureOnly")) {
            $snapshotStatusHtml = Publish-SnapshotStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("workloadDomain")) {
            $snapshotStatusHtml = Publish-SnapshotStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
        }

        # Generating the Password Expiry Health Data using PowerShell Request Functions
        Write-LogMessage -Type INFO -Message "Generating the Password Expiry Report for $workflowMessage."
        if ($PsBoundParameters.ContainsKey("allDomains") -and $PsBoundParameters.ContainsKey("failureOnly")) {
            $localPasswordHtml = Publish-LocalUserExpiry -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -sddcRootPass $sddcManagerRootPass -allDomains -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("allDomains")) {
            $localPasswordHtml = Publish-LocalUserExpiry -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -sddcRootPass $sddcManagerRootPass -allDomains
        }
        if ($PsBoundParameters.ContainsKey("workloadDomain") -and $PsBoundParameters.ContainsKey("failureOnly")) {
            $localPasswordHtml = Publish-LocalUserExpiry -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -sddcRootPass $sddcManagerRootPass -workloadDomain $workloadDomain -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("workloadDomain")) {
            $localPasswordHtml = Publish-LocalUserExpiry -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -sddcRootPass $sddcManagerRootPass -workloadDomain $workloadDomain
        }

        # Generating the NSX Transport Node Health Data Using PowerShell Request Functions
        Write-LogMessage -type INFO -Message "Generating the NSX Transport Node Report for $workflowMessage."
        if ($PsBoundParameters.ContainsKey('allDomains') -and $PsBoundParameters.ContainsKey('failureOnly')) {
            $nsxTransportNodeHtml = Publish-NsxtTransportNodeStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains -failureOnly
        }
        elseif ($PsBoundParameters.ContainsKey('allDomains')) {
            $nsxTransportNodeHtml = Publish-NsxtTransportNodeStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains
        }
        if ($PsBoundParameters.ContainsKey('workloadDomain') -and $PsBoundParameters.ContainsKey('failureOnly')) {
            $nsxTransportNodeHtml = Publish-NsxtTransportNodeStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain -failureOnly
        }
        elseif ($PsBoundParameters.ContainsKey('workloadDomain')) {
            $nsxTransportNodeHtml = Publish-NsxtTransportNodeStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
        }

        # Generating the NSX Tier-0 Gateway BGP Health Data Using PowerShell Request Functions
        Write-LogMessage -type INFO -Message "Generating the NSX Tier-0 Gateway BGP Report for $workflowMessage."
        if ($PsBoundParameters.ContainsKey("allDomains") -and $PsBoundParameters.ContainsKey("failureOnly")) {
            $nsxTier0BgpHtml = Publish-NsxtTier0BgpStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("allDomains")) {
            $nsxTier0BgpHtml = Publish-NsxtTier0BgpStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains
        }
        if ($PsBoundParameters.ContainsKey("workloadDomain") -and $PsBoundParameters.ContainsKey("failureOnly")) {
            $nsxTier0BgpHtml = Publish-NsxtTier0BgpStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("workloadDomain")) {
            $nsxTier0BgpHtml = Publish-NsxtTier0BgpStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
        }

        # Generating the Disk Capacity Health Data Using PowerShell Request Functions
        Write-LogMessage -Type INFO -Message "Generating the Disk Capacity Report for $workflowMessage.'"
        if ($PsBoundParameters.ContainsKey("allDomains") -and $PsBoundParameters.ContainsKey("failureOnly")) {
            $storageCapacityHealthHtml = Publish-StorageCapacityHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -rootPass $sddcManagerRootPass -allDomains -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("allDomains")) {
            $storageCapacityHealthHtml = Publish-StorageCapacityHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -rootPass $sddcManagerRootPass -allDomains
        }
        if ($PsBoundParameters.ContainsKey("workloadDomain") -and $PsBoundParameters.ContainsKey("failureOnly")) {
            $storageCapacityHealthHtml = Publish-StorageCapacityHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -rootPass $sddcManagerRootPass -workloadDomain $workloadDomain -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("workloadDomain")) {
                $storageCapacityHealthHtml = Publish-StorageCapacityHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -rootPass $sddcManagerRootPass -workloadDomain $workloadDomain
        }

        # Combine all information gathered into a single HTML report
        if ($PsBoundParameters.ContainsKey("allDomains")) {
            $reportData = "<h1>SDDC Manager: $sddcManagerFqdn</h1>"
        } else {
            $reportData = "<h1>Workload Domain: $workloadDomain</h1>"
        }
        $reportData += $serviceHtml
        $reportData += $componentConnectivityHtml
        $reportData += $localPasswordHtml
        $reportData += $certificateHtml
        $reportData += $backupStatusHtml
        $reportData += $snapshotStatusHtml
        $reportData += $dnsHtml
        $reportData += $ntpHtml
        $reportData += $vcenterHtml
        $reportData += $esxiHtml
        $reportData += $vsanHtml
        $reportData += $vsanPolicyHtml
        $reportData += $nsxtHtml
        $reportData += $nsxtEdgeClusterHtml
        $reportData += $nsxtEdgeNodeHtml
        $reportData += $nsxTransportNodeHtml
        $reportData += $nsxTier0BgpHtml
        $reportData += $storageCapacityHealthHtml

        if ($PsBoundParameters.ContainsKey("darkMode")) {
            $reportHeader = Get-ClarityReportHeader -dark 
        } else {
            $reportHeader = Get-ClarityReportHeader
        }
        $reportNavigation = Get-ClarityReportNavigation -reportType health
        $reportFooter = Get-ClarityReportFooter
        $report = $reportHeader
        $report += $reportNavigation
        $report += $reportData
        $report += $reportFooter

        # Generate the report to an HTML file and then open it in the default browser
        Write-LogMessage -Type INFO -Message "Generating the final report and saving to ($reportName)."
        $report | Out-File $reportName
        Invoke-Item $reportName
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Invoke-VcfHealthReport

Function Invoke-VcfAlertReport {
    <#
        .SYNOPSIS
        Generates the alert report for a VMware Cloud Foundation instance.

        .DESCRIPTION
        The Invoke-VcfAlertReport provides a single cmdlet to generates the alert report for a VMware Cloud Foundation instance.

        .EXAMPLE
        Invoke-VcfAlertReport -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser admin@local -sddcManagerPass VMw@re1!VMw@re1! -reportPath F:\Reporting -allDomains
        This example generates the alert report across a VMware Cloud Foundation instance.

        .EXAMPLE
        Invoke-VcfAlertReport -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser admin@local -sddcManagerPass VMw@re1!VMw@re1! -reportPath F:\Reporting -allDomains -failureOnly
        This example generates the alert report across a VMware Cloud Foundation instance but for only failed items.

        .EXAMPLE
        Invoke-VcfAlertReport -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser admin@local -sddcManagerPass VMw@re1!VMw@re1! -reportPath F:\Reporting -workloadDomain sfo-w01
        This example generates the alert report for a specific workload domain in a VMware Cloud Foundation instance.

        .EXAMPLE
        Invoke-VcfAlertReport -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser admin@local -sddcManagerPass VMw@re1!VMw@re1! -reportPath F:\Reporting -workloadDomain sfo-w01 -failureOnly
        This example generates the alert report for a specific workload domain in a VMware Cloud Foundation instance but for only failed items.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerFqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerUser,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerPass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$reportPath,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific--WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$darkMode
    )

    Try {
        Clear-Host; Write-Host ""

        Start-CreateReportDirectory -path $reportPath -sddcManagerFqdn $sddcManagerFqdn -reportType alert # Setup Report Location and Report File
        if (!(Test-Path -Path $reportPath)) {Write-Warning "Unable to locate report path $reportPath, enter a valid path and try again"; Write-Host ""; Break }
        if ($message = Test-VcfHealthPrereq) {Write-Warning $message; Write-Host ""; Break }
        if ($PsBoundParameters.ContainsKey("allDomains")) {
            $workflowMessage = "VMware Cloud Foundation instance ($sddcManagerFqdn)"
        } else {
            $workflowMessage = "Workload Domain ($workloadDomain)"
        }
        Start-SetupLogFile -Path $reportPath -ScriptName $MyInvocation.MyCommand.Name # Setup Log Location and Log File
        Write-LogMessage -Type INFO -Message "Starting the process of creating an Alert Report for $workflowMessage." -Colour Yellow
        Write-LogMessage -Type INFO -Message "Setting up the log file to path $logfile."
        Write-LogMessage -Type INFO -Message "Setting up report folder and report $reportName."  

        # Generate vCenter Server Alerts Using PowerShell Function
        Write-LogMessage -Type INFO -Message "Generating the vCenter Server alerts for $workflowMessage."
        if ($PsBoundParameters.ContainsKey("allDomains") -and $PsBoundParameters.ContainsKey("failureOnly")) {
            $vCenterAlertHtml = Publish-VcenterAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -alldomains -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("allDomains")) {
            $vCenterAlertHtml = Publish-VcenterAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -alldomains
        }
        if ($PsBoundParameters.ContainsKey("workloadDomain") -and $PsBoundParameters.ContainsKey("failureOnly")) {
            $vCenterAlertHtml = Publish-VcenterAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("workloadDomain")) {
            $vCenterAlertHtml = Publish-VcenterAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
        }

        # Generate ESXi Alerts Using PowerShell Function
        Write-LogMessage -type INFO -Message "Generating the ESXi host alerts for $workflowMessage."
        if ($PsBoundParameters.ContainsKey("allDomains") -and $PsBoundParameters.ContainsKey("failureOnly")) {
            $esxiAlertHtml = Publish-EsxiAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -alldomains -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("allDomains")) {
            $esxiAlertHtml = Publish-EsxiAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -alldomains
        }
        if ($PsBoundParameters.ContainsKey("workloadDomain") -and $PsBoundParameters.ContainsKey("failureOnly")) {
            $esxiAlertHtml = Publish-EsxiAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("workloadDomain")) {
            $esxiAlertHtml = Publish-EsxiAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
        }
        
        # Generate vSAN Alerts Using PowerShell Function
        Write-LogMessage -type INFO -Message "Generating the vSAN alerts for $workflowMessage."
        if ($PsBoundParameters.ContainsKey("allDomains") -and $PsBoundParameters.ContainsKey("failureOnly")) {
            $vsanAlertHtml = Publish-VsanAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -alldomains -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("allDomains")) {
            $vsanAlertHtml = Publish-VsanAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -alldomains
        }
        if ($PsBoundParameters.ContainsKey("workloadDomain") -and $PsBoundParameters.ContainsKey("failureOnly")) {
            $vsanAlertHtml = Publish-VsanAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("workloadDomain")) {
            $vsanAlertHtml = Publish-VsanAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
        }
        
        # Generate NSX-T Data Center Alerts Using PowerShell Function
        Write-LogMessage -type INFO -Message "Generating the NSX-T Data Center alerts for $workflowMessage."
        if ($PsBoundParameters.ContainsKey("allDomains") -and $PsBoundParameters.ContainsKey("failureOnly")) {
            $nsxtAlertHtml = Publish-NsxtAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -alldomains -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("allDomains")) {
            $nsxtAlertHtml = Publish-NsxtAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -alldomains
        }
        if ($PsBoundParameters.ContainsKey("workloadDomain") -and $PsBoundParameters.ContainsKey("failureOnly")) {
            $nsxtAlertHtml = Publish-NsxtAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain -failureOnly
        } elseif ($PsBoundParameters.ContainsKey("workloadDomain")) {
            $nsxtAlertHtml = Publish-NsxtAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
        }
        
        # Combine all information gathered into a single HTML report
        if ($PsBoundParameters.ContainsKey("allDomains")) {
            $reportData = "<h1>SDDC Manager: $sddcManagerFqdn</h1>"
        } else {
            $reportData = "<h1>Workload Domain: $workloadDomain</h1>"
        }
        $reportData += $vCenterAlertHtml
        $reportData += $esxiAlertHtml
        $reportData += $vsanAlertHtml
        $reportData += $nsxtAlertHtml

        if ($PsBoundParameters.ContainsKey("darkMode")) {
            $reportHeader = Get-ClarityReportHeader -dark 
        } else {
            $reportHeader = Get-ClarityReportHeader
        }
        $reportNavigation = Get-ClarityReportNavigation -reportType alert
        $reportFooter = Get-ClarityReportFooter
        $report = $reportHeader
        $report += $reportNavigation
        $report += $reportData
        $report += $reportFooter
        
        # Generate the report to an HTML file and then open it in the default browser
        Write-LogMessage -Type INFO -Message "Generating the final report and saving to ($reportName)."
        $report | Out-File $reportName
        Invoke-Item $reportName
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Invoke-VcfAlertReport

Function Invoke-VcfConfigReport {
    <#
        .SYNOPSIS
        Generates the configuration report

        .DESCRIPTION
        The Invoke-VcfConfigReport provides a single cmdlet to generates a configuration report for a VMware Cloud Foundation instance.

        .EXAMPLE
        Invoke-VcfConfigReport -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser admin@local -sddcManagerPass VMw@re1!VMw@re1! -reportPath F:\Reporting -allDomains
        This example generates the configuration report across a VMware Cloud Foundation instance.

        .EXAMPLE
        Invoke-VcfConfigReport -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser admin@local -sddcManagerPass VMw@re1!VMw@re1! -reportPath F:\Reporting -workloadDomain sfo-w01
        This example generates the configuration report for a specific Workload Domain within a VMware Cloud Foundation instance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerFqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerUser,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerPass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$reportPath,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific--WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$darkMode
    )

    Try {
        Clear-Host; Write-Host ""

        Start-CreateReportDirectory -path $reportPath -sddcManagerFqdn $sddcManagerFqdn -reportType config # Setup Report Location and Report File
        if (!(Test-Path -Path $reportPath)) {Write-Warning "Unable to locate report path $reportPath, enter a valid path and try again"; Write-Host ""; Break }
        if ($message = Test-VcfHealthPrereq) {Write-Warning $message; Write-Host ""; Break }
        if ($PsBoundParameters.ContainsKey("allDomains")) {
            $workflowMessage = "VMware Cloud Foundation instance ($sddcManagerFqdn)"
        } else {
            $workflowMessage = "Workload Domain ($workloadDomain)"
        }
        Start-SetupLogFile -Path $reportPath -ScriptName $MyInvocation.MyCommand.Name # Setup Log Location and Log File
        Write-LogMessage -Type INFO -Message "Starting the Process of Creating a Configuration Report for $workflowMessage." -Colour Yellow
        Write-LogMessage -Type INFO -Message "Setting up the log file to path $logfile."
        Write-LogMessage -Type INFO -Message "Setting up report folder and report $reportName."

        Write-LogMessage -Type INFO -Message "Collecting ESXi Core Dump Configuration for $workflowMessage."
        if ($PsBoundParameters.ContainsKey("allDomains")) {
            $esxiCoreDumpHtml = Publish-EsxiCoreDumpConfig -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -alldomains -html
        }
        else {
            $esxiCoreDumpHtml = Publish-EsxiCoreDumpConfig -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain -html
        }
        
        # Combine all information gathered into a single HTML report
        if ($PsBoundParameters.ContainsKey("allDomains")) {
            $reportData = "<h1>SDDC Manager: $sddcManagerFqdn</h1>"
        } else {
            $reportData = "<h1>Workload Domain: $workloadDomain</h1>"
        }
        $reportData += "$esxiCoreDumpHtml"

        if ($PsBoundParameters.ContainsKey("darkMode")) {
            $reportHeader = Get-ClarityReportHeader -dark 
        } else {
            $reportHeader = Get-ClarityReportHeader
        }
        $reportNavigation = Get-ClarityReportNavigation -reportType config
        $reportFooter = Get-ClarityReportFooter
        $report = $reportHeader
        $report += $reportNavigation
        $report += $reportData
        $report += $reportFooter

        # Generate the report to an HTML file and then open it in the default browser
        Write-LogMessage -Type INFO -Message "Generating the Final Report and Saving to ($reportName)."
        $report | Out-File $reportName
        Invoke-Item $reportName
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Invoke-VcfConfigReport

Function Invoke-VcfUpgradePrecheck {
    <#
        .SYNOPSIS
        Perform upgrade precheck

        .DESCRIPTION
        The Invoke-VcfUpgradePrecheck runs an upgrade precheck for a Workload Domain

        .EXAMPLE
        Invoke-VcfUpgradePrecheck -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser admin@local -sddcManagerPass VMw@re1!VMw@re1! -reportPath F:\Reporting -workloadDomain sfo-w01
        This example runs a health check for a specific Workload Domain within an SDDC Manager instance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerFqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerUser,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerPass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$reportPath,
        [Parameter (ParameterSetName = 'Specific--WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$darkMode
    )

    Try {

        Clear-Host; Write-Host ""

        Start-CreateReportDirectory -path $reportPath -sddcManagerFqdn $sddcManagerFqdn -reportType upgrade # Setup Report Location and Report File
        if (!(Test-Path -Path $reportPath)) {Write-Warning "Unable to locate report path $reportPath, enter a valid path and try again"; Write-Host ""; Break }
        if ($message = Test-VcfHealthPrereq) {Write-Warning $message; Write-Host ""; Break }
        $workflowMessage = "Workload Domain ($workloadDomain)"
        Start-SetupLogFile -Path $reportPath -ScriptName $MyInvocation.MyCommand.Name # Setup Log Location and Log File
        Write-LogMessage -Type INFO -Message "Starting the Process of Running an Upgrade Precheck for $workflowMessage." -Colour Yellow
        Write-LogMessage -Type INFO -Message "Setting up the log file to path $logfile."
        Write-LogMessage -Type INFO -Message "Setting up report folder and report $reportName."

        if (Test-VCFConnection -server $sddcManagerFqdn) {
            if (Test-VCFAuthentication -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass) {
                $jsonSpec = '{ "resources" : [ { "resourceId" : "'+ (Get-VCFWorkloadDomain | Where-Object {$_.name -eq $workloadDomain}).id+'", "type" : "DOMAIN" } ] }'
                $task = Start-VCFSystemPrecheck -json $jsonSpec
                Write-LogMessage -Type INFO -Message "Waiting for Upgrade Precheck Task ($($task.name)) with Id ($($task.id)) to Complete."
                Do { $status = Get-VCFSystemPrecheckTask -id $task.id } While ($status.status -eq "IN_PROGRESS")
                Write-LogMessage -Type INFO -Message "Task ($($task.name)) with Task Id ($($task.id)) completed with status ($($status.status))."
                $allChecksObject = New-Object System.Collections.ArrayList
                foreach ($subTask in $status.subTasks) {
                    $elementObject = New-Object -TypeName psobject
                    $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $subTask.resources.type
                    if ($subTask.resources.type -eq "ESX") {
                        $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue (Get-VCFHost -id $subTask.resources.resourceId).fqdn
                    }
                    elseif ($subTask.resources.type -eq "VCENTER") {
                        $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue (Get-VCFvCenter -id $subTask.resources.resourceId).fqdn
                    }
                    elseif ($subTask.resources.type -eq "CLUSTER") {
                        $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue (Get-VCFCluster -id $subTask.resources.resourceId).name
                    }
                    elseif ($subTask.resources.type -eq "VSAN") {
                        $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue (Get-VCFCluster -id $subTask.resources.resourceId).primaryDatastoreName
                    }
                    elseif ($subTask.resources.type -eq "DEPLOYMENT_CONFIGURATION") {
                        $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue (Get-VCFManager -id $subTask.resources.resourceId).fqdn
                    }
                    elseif ($subTask.resources.type -eq "VRSLCM") {
                        $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue (Get-VCFvRSLCM -id $subTask.resources.resourceId).fqdn
                    }
                    elseif ($subTask.resources.type -eq "VROPS") {
                        $id = $subTask.resources.resourceId + ":vrops"
                        $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue (Get-VCFvROPS | Where-Object {$_.id -eq $id}).loadBalancerFqdn
                    }
                    elseif ($subTask.resources.type -eq "VRLI") {
                        $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue (Get-VCFvRLI -id $subTask.resources.resourceId).loadBalancerFqdn
                    }
                    elseif ($subTask.resources.type -eq "VRA") {
                        $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue (Get-VCFvRA -id $subTask.resources.resourceId).loadBalancerFqdn
                    }
                    else {
                        $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $subTask.resources.resourceId
                    }
                    $elementObject | Add-Member -NotePropertyName 'Precheck Task' -NotePropertyValue $subTask.name
                    if ($subTask.status -eq "SUCCESSFUL") {
                        $alert = "GREEN"
                    } elseif ($subTask.status -eq "WARNING") {
                        $alert = "YELLOW"
                    } elseif ($subTask.status -eq "FAILED") {
                        $alert = "RED"
                    }
                    $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
                    $allChecksObject += $elementObject
                }
                $allChecksObject = $allChecksObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="upgrade-precheck"></a><h3>Upgrade Precheck</h3>' -As Table
                $allChecksObject = Convert-CssClass -htmldata $allChecksObject
            }
        }

        # Combine all information gathered into a single HTML report
        $reportData = "<h1>Workload Domain: $workloadDomain</h1>"
        $reportData += $allChecksObject

        if ($PsBoundParameters.ContainsKey("darkMode")) {
            $reportHeader = Get-ClarityReportHeader -dark 
        } else {
            $reportHeader = Get-ClarityReportHeader
        }
        $reportNavigation = Get-ClarityReportNavigation -reportType upgrade
        $reportFooter = Get-ClarityReportFooter
        $report = $reportHeader
        $report += $reportNavigation
        $report += $reportData
        $report += $reportFooter

        # Generate the report to an HTML file and then open it in the default browser
        Write-LogMessage -Type INFO -Message "Generating the Final Report and Saving to ($reportName)."
        $report | Out-File $reportName
        Invoke-Item $reportName
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Invoke-VcfUpgradePrecheck

Function Invoke-VcfPasswordPolicy {
    <#
        .SYNOPSIS
        Generate a password policy report

        .DESCRIPTION
        The Invoke-VcfPasswordPolicy runs a password policy report for a Workload Domain

        .EXAMPLE
        Invoke-VcfPasswordPolicy -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser admin@local -sddcManagerPass VMw@re1!VMw@re1! -reportPath F:\Reporting -allDomains
        This example runs a password policy report for all Workload Domain within an SDDC Manager instance.

        .EXAMPLE
        Invoke-VcfPasswordPolicy -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser admin@local -sddcManagerPass VMw@re1!VMw@re1! -reportPath F:\Reporting -workloadDomain sfo-w01
        This example runs a password policy report for a specific Workload Domain within an SDDC Manager instance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerFqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerUser,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerPass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$reportPath,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific--WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$darkMode
    )

    Try {

        Clear-Host; Write-Host ""

        Start-CreateReportDirectory -path $reportPath -sddcManagerFqdn $sddcManagerFqdn -reportType policy # Setup Report Location and Report File
        if (!(Test-Path -Path $reportPath)) {Write-Warning "Unable to locate report path $reportPath, enter a valid path and try again"; Write-Host ""; Break }
        if ($message = Test-VcfHealthPrereq) {Write-Warning $message; Write-Host ""; Break }
        if ($PsBoundParameters.ContainsKey("allDomains")) {
            $workflowMessage = "VMware Cloud Foundation instance ($sddcManagerFqdn)"
        } else {
            $workflowMessage = "Workload Domain ($workloadDomain)"
        }
        Start-SetupLogFile -Path $reportPath -ScriptName $MyInvocation.MyCommand.Name # Setup Log Location and Log File
        Write-LogMessage -Type INFO -Message "Starting the Process of Running a Password Policy Report for $workflowMessage." -Colour Yellow
        Write-LogMessage -Type INFO -Message "Setting up the log file to path $logfile."
        Write-LogMessage -Type INFO -Message "Setting up report folder and report $reportName."

        # Collect vCenter Server Password Policies
        if ($PsBoundParameters.ContainsKey('allDomains')) { 
            Write-LogMessage -Type INFO -Message "Collecting vCenter Server Password Policy Configuration for $workflowMessage."
            $vcenterPolicyHtml = Publish-VcenterPolicy -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains
        }
        else {
            Write-LogMessage -Type INFO -Message "Collecting vCenter Server Policy Configuration for $workflowMessage."
            $vcenterPolicyHtml = Publish-VcenterPolicy -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
        }

        # Collect ESXi Password Policies
        if ($PsBoundParameters.ContainsKey('allDomains')) { 
            Write-LogMessage -Type INFO -Message "Collecting ESXi Password Policy Configuration for $workflowMessage."
            $esxiPolicyHtml = Publish-EsxiPolicy -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains
        }
        else {
            Write-LogMessage -Type INFO -Message "Collecting ESXi Password Policy Configuration for $workflowMessage."
            $esxiPolicyHtml = Publish-EsxiPolicy -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
        }

        # Collect NSX-T Data Center Password Policies
        if ($PsBoundParameters.ContainsKey('allDomains')) { 
            Write-LogMessage -Type INFO -Message "Collecting NSX-T Data Center Password Policy Configuration for $workflowMessage."
            $nsxtPolicyHtml = Publish-NsxtPolicy -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains
        }
        else {
            Write-LogMessage -Type INFO -Message "Collecting NSX-T Data Center Password Policy Configuration for $workflowMessage."
            $nsxtPolicyHtml = Publish-NsxtPolicy -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
        }
        
        # Combine all information gathered into a single HTML report
        if ($PsBoundParameters.ContainsKey("allDomains")) {
            $reportData = "<h1>SDDC Manager: $sddcManagerFqdn</h1>"
        } else{
            $reportData = "<h1>Workload Domain: $workloadDomain</h1>"
        }
        $reportData += $vcenterPolicyHtml
        $reportData += $esxiPolicyHtml
        $reportData += $nsxtPolicyHtml

        if ($PsBoundParameters.ContainsKey("darkMode")) {
            $reportHeader = Get-ClarityReportHeader -dark 
        } else {
            $reportHeader = Get-ClarityReportHeader
        }
        $reportNavigation = Get-ClarityReportNavigation -reportType policy
        $reportFooter = Get-ClarityReportFooter
        $report = $reportHeader
        $report += $reportNavigation
        $report += $reportData
        $report += $reportFooter

        # Generate the report to an HTML file and then open it in the default browser
        Write-LogMessage -Type INFO -Message "Generating the Final Report and Saving to ($reportName)."
        $report | Out-File $reportName
        Invoke-Item $reportName
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Invoke-VcfPasswordPolicy

Function Invoke-VcfOverviewReport {
    <#
        .SYNOPSIS
        Generates the system overview report

        .DESCRIPTION
        The Invoke-VcfOverviewReport provides a single cmdlet to generates a system overview report for a VMware Cloud Foundation instance.

        .EXAMPLE
        Invoke-VcfOverviewReport -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser admin@local -sddcManagerPass VMw@re1!VMw@re1! -reportPath F:\Reporting
        This example generates the system overview report for a VMware Cloud Foundation instance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerFqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerUser,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerPass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$reportPath,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$darkMode
    )

    Try {
        Clear-Host; Write-Host ""

        Start-CreateReportDirectory -path $reportPath -sddcManagerFqdn $sddcManagerFqdn -reportType overview # Setup Report Location and Report File
        if (!(Test-Path -Path $reportPath)) {Write-Warning "Unable to locate report path $reportPath, enter a valid path and try again"; Write-Host ""; Break }
        if ($message = Test-VcfHealthPrereq) {Write-Warning $message; Write-Host ""; Break }
        $workflowMessage = "VMware Cloud Foundation instance ($sddcManagerFqdn)"
        Start-SetupLogFile -Path $reportPath -ScriptName $MyInvocation.MyCommand.Name # Setup Log Location and Log File
        Write-LogMessage -Type INFO -Message "Starting the Process of Creating a System Overview Report for $workflowMessage." -Colour Yellow
        Write-LogMessage -Type INFO -Message "Setting up the log file to path $logfile."
        Write-LogMessage -Type INFO -Message "Setting up report folder and report $reportName."

        Write-LogMessage -Type INFO -Message "Generating System Overview Report for $workflowMessage."
        $vcfOverviewHtml = Publish-VcfSystemOverview -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass
        
        $reportData += $vcfOverviewHtml

        if ($PsBoundParameters.ContainsKey("darkMode")) {
            $reportHeader = Get-ClarityReportHeader -dark 
        } else {
            $reportHeader = Get-ClarityReportHeader
        }
        $reportNavigation = Get-ClarityReportNavigation -reportType overview
        $reportFooter = Get-ClarityReportFooter
        $report = $reportHeader
        $report += $reportNavigation
        $report += $reportData
        $report += $reportFooter

        # Generate the report to an HTML file and then open it in the default browser
        Write-LogMessage -Type INFO -Message "Generating the Final Report and Saving to ($reportName)."
        $report | Out-File $reportName
        Invoke-Item $reportName
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Invoke-VcfOverviewReport

##########################################  E N D   O F   F U N C T I O N S  ##########################################
#######################################################################################################################


#######################################################################################################################
#############################  S O S   J S O N   E X T R A C T I O N   F U N C T I O N S   ############################

Function Request-SoSHealthJson {
    <#
        .SYNOPSIS
        Run SoS and save the JSON output.

        .DESCRIPTION
        The Request-SoSHealthJson cmdlet connects to SDDC Manager, runs an SoS Health collection to JSON, and saves the
        JSON file to the local file system.

        .EXAMPLE
        Request-SoSHealthJson -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -rootPass VMw@re1! -reportPath F:\Precheck\HealthReports -allDomains
        This example runs an SoS Health collection on all domains on the SDDC and saves the JSON output to the local file system.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$rootPass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$reportPath,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain
    )

    Try {
        if ($PsBoundParameters.ContainsKey("allDomains")) { 
            $command = "/opt/vmware/sddc-support/sos --health-check --skip-known-host-check --json-output-dir /tmp/jsons --domain-name ALL"
            $reportDestination = ($reportPath + "\" + $server.Split(".")[0] + "-all-health-results.json")
        } elseif ($PsBoundParameters.ContainsKey("workloadDomain")) {
            $command = "/opt/vmware/sddc-support/sos --health-check --skip-known-host-check --json-output-dir /tmp/jsons --domain-name " + $workloadDomain
            $reportDestination = ($reportPath + "\" + $workloadDomain + "-all-health-results.json")
        }
        Invoke-SddcCommand -server $server -user $user -pass $pass -rootPass $rootPass -command $command | Out-Null
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT)) {
                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            Copy-VMGuestFile -Source "/tmp/jsons/health-results.json" -Destination $reportDestination -VM $server.Split(".")[0] -GuestToLocal -GuestUser root -GuestPassword $rootPass
                            $temp = Get-Content -Path $reportDestination; $temp = $temp -replace '""', '"-"'; $temp | Out-File $reportDestination
                            $reportDestination
                        }
                        Disconnect-VIServer -Server $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                    }
                }
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-SoSHealthJson

Function Publish-CertificateHealth {
    <#
        .SYNOPSIS
        Formats the Certificate Health data from the SoS JSON output.

        .DESCRIPTION
        The Publish-CertificateHealth cmdlet formats the Certificate Health data from the SoS JSON output and publishes
        it as either a standard PowerShell object or an HTML object. 

        .EXAMPLE
        Publish-CertificateHealth -json <file-name>
        This example extracts and formats the Certificate Health data as a PowerShell object from the JSON file.

        .EXAMPLE
        Publish-CertificateHealth -json <file-name> -html
        This example extracts and formats the Certificate Health data as an HTML object from the JSON file.

        .EXAMPLE
        Publish-CertificateHealth -json <file-name> -failureOnly
        This example extracts and formats the Certificate Health data as a PowerShell object from the JSON file for only the failed items.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$json,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (!(Test-Path -Path $json)) {
            Write-Error "Unable to find JSON file at location ($json)" -ErrorAction Stop
        }
        else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }

        # ESXi Certificate Health
        $outputObject = New-Object System.Collections.ArrayList
        $jsonInputData = $targetContent.'Certificates'.'Certificate Status'.ESXi # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey('failureOnly')) {
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
        }
        else {
            $outputObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
        }
        
        # Certificate Health (Except ESXi)
        $customObject = New-Object System.Collections.ArrayList
        $inputData = $targetContent.'Certificates'.'Certificate Status' # Extract Data from the provided SOS JSON
        $inputData.PSObject.Properties.Remove('ESXI')
        foreach ($component in $inputData.PsObject.Properties.Value) { 
            foreach ($element in $component.PsObject.Properties.Value) { 
                $elementObject = New-Object -TypeName psobject
                $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue ($element.area -Split (':'))[0].Trim()
                $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue ($element.area -Split (':'))[-1].Trim()
                $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $element.alert
                $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $element.message
                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                    if (($element.status -eq 'FAILED')) {
                        $customObject += $elementObject
                    }
                }
                else {
                    $customObject += $elementObject
                }
            }
        }

        $outputObject += $customObject # Combined ESXi Certificate Health with Remaining Components

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey('html')) { 
            if ($outputObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="security-certificate"></a><h3>Certificate Health Status</h3>' -PostContent '<p>No issues found.</p>' 
            } else {
                $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="security-certificate"></a><h3>Certificate Health Status</h3>' -As Table
            }
            $outputObject = Convert-CssClass -htmldata $outputObject
            $outputObject
        }
        else {
            $outputObject | Sort-Object Component, Resource 
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-CertificateHealth

Function Publish-ConnectivityHealth {
    <#
        .SYNOPSIS
        Formats the Connectivity Health data from the SoS JSON output.

        .DESCRIPTION
        The Publish-ConnectivityHealth cmdlet formats the Connectivity Health data from the SoS JSON output and
        publishes it as either a standard PowerShell object or an HTML object. 

        .EXAMPLE
        Publish-ConnectivityHealth -json <file-name>
        This example extracts and formats the Connectivity Health data as a PowerShell object from the JSON file.

        .EXAMPLE
        Publish-ConnectivityHealth -json <file-name> -html
        This example extracts and formats the Connectivity Health data as an HTML object from the JSON file.

        .EXAMPLE
        Publish-ConnectivityHealth -json <file-name> -failureOnly
        This example extracts and formats the Connectivity Health data as a PowerShell object from the JSON file for only the failed items.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$json,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (!(Test-Path -Path $json)) {
            Write-Error "Unable to find JSON file at location ($json)" -ErrorAction Stop
        }
        else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }

        $customObject = New-Object System.Collections.ArrayList
        # ESXi SSH Status
        $jsonInputData = $targetContent.Connectivity.'Connectivity Status'.'ESXi SSH Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey('failureOnly')) {
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
        }
        else {
            $outputObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
        }
        $customObject += $outputObject # Adding individual component to main customObject

        # ESXi API Status
        $jsonInputData = $targetContent.Connectivity.'Connectivity Status'.'ESXi API Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey('failureOnly')) {
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
        }
        else {
            $outputObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
        }
        $customObject += $outputObject # Adding individual component to main customObject

        # Additional Items Status
        $jsonInputData = $targetContent.Connectivity.'Connectivity Status' # Extract Data from the provided SOS JSON
        $jsonInputData.PSObject.Properties.Remove('ESXi SSH Status')
        $jsonInputData.PSObject.Properties.Remove('ESXi API Status')
        if ($PsBoundParameters.ContainsKey('failureOnly')) {
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
        }
        else {
            $outputObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
        }
        $customObject += $outputObject # Adding individual component to main customObject

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey('html')) {
            if ($outputObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="general-connectivity"></a><h3>Connectivity Health Status</h3>' -PostContent '<p>No issues found.</p>' 
            } else {
                $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="general-connectivity"></a><h3>Connectivity Health Status</h3>' -As Table
            }
            $customObject = Convert-CssClass -htmldata $customObject
            $customObject
        }
        else {
            $customObject | Sort-Object Component, Resource 
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-ConnectivityHealth

Function Publish-DnsHealth {
    <#
        .SYNOPSIS
        Formats the DNS Health data from the SoS JSON output.

        .DESCRIPTION
        The Publish-DnsHealth cmdlet formats the DNS Health data from the SoS JSON output and publishes it as
        either a standard PowerShell object or an HTML object. 

        .EXAMPLE
        Publish-DnsHealth -json <file-name>
        This example extracts and formats the DNS Health data as a PowerShell object from the JSON file.

        .EXAMPLE
        Publish-DnsHealth -json <file-name> -html
        This example extracts and formats the DNS Health data as an HTML object from the JSON file.

        .EXAMPLE
        Publish-DnsHealth -json <file-name> -failureOnly
        This example extracts and formats the DNS Health data as a PowerShell object from the JSON file for only the failed items.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$json,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (!(Test-Path -Path $json)) {
            Write-Error "Unable to find JSON file at location ($json)" -ErrorAction Stop
        } else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }

        # Forward Lookup Health Status
        $allForwardLookupObject = New-Object System.Collections.ArrayList
        $jsonInputData = $targetContent.'DNS lookup Status'.'Forward lookup Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) {
            $allForwardLookupObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
        } else {
            $allForwardLookupObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
        }

        # Reverse Lookup Health Status
        $allReverseLookupObject = New-Object System.Collections.ArrayList
        $jsonInputData = $targetContent.'DNS lookup Status'.'Reverse lookup Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) {
            $allReverseLookupObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
        } else {
            $allReverseLookupObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) { 
            if ($allForwardLookupObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $allForwardLookupObject = $allForwardLookupObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="infra-dns-forward"></a><h3>DNS Forward Lookup Health Status</h3>' -PostContent '<p>No issues found.</p>' 
            } else {
                $allForwardLookupObject = $allForwardLookupObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="infra-dns-forward"></a><h3>DNS Forward Lookup Health Status</h3>' -As Table
            }
            $allForwardLookupObject = Convert-CssClass -htmldata $allForwardLookupObject
            $allForwardLookupObject
            if ($allReverseLookupObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $allReverseLookupObject = $allReverseLookupObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="infra-dns-reverse"></a><h3>DNS Reverse Lookup Health Status</h3>' -PostContent '<p>No issues found.</p>' 
            } else {
                $allReverseLookupObject = $allReverseLookupObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="infra-dns-reverse"></a><h3>DNS Reverse Lookup Health Status</h3>' -As Table
            }
            $allReverseLookupObject = Convert-CssClass -htmldata $allReverseLookupObject
            $allReverseLookupObject
        } else {
            $allForwardLookupObject | Sort-Object Component, Resource
            $allReverseLookupObject | Sort-Object Component, Resource
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-DnsHealth

Function Publish-EsxiHealth {
    <#
        .SYNOPSIS
        Formats the ESXi Health data from the SoS JSON output.

        .DESCRIPTION
        The Publish-EsxiHealth cmdlet formats the ESXi Health data from the SoS JSON output and publishes it as
        either a standard PowerShell object or an HTML object. 

        .EXAMPLE
        Publish-EsxiHealth -json <file-name>
        This example extracts and formats the ESXi Health data as a PowerShell object from the JSON file.

        .EXAMPLE
        Publish-EsxiHealth -json <file-name> -html
        This example extracts and formats the ESXi Health data as an HTML object from the JSON file.

        .EXAMPLE
        Publish-EsxiHealth -json <file-name> -failureOnly
        This example extracts and formats the ESXi Health data as a PowerShell object from the JSON file for only the failed items.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$json,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (!(Test-Path -Path $json)) {
            Write-Error "Unable to find JSON file at location ($json)" -ErrorAction Stop
        }
        else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }

        # ESXi Overall Health Status
        $allOverallHealthObject = New-Object System.Collections.ArrayList
        $jsonInputData = $targetContent.Compute.'ESXi Overall Health' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey('failureOnly')) {
            $allOverallHealthObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
        }
        else {
            $allOverallHealthObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
        }

        # ESXi Core Dump Status
        $allCoreDumpObject = New-Object System.Collections.ArrayList
        $jsonInputData = $targetContent.General.'ESXi Core Dump Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey('failureOnly')) {
            $allCoreDumpObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
        }
        else {
            $allCoreDumpObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
        }
        
        # ESXi License Status
        $allLicenseObject = New-Object System.Collections.ArrayList
        $jsonInputData = $targetContent.Compute.'ESXi License Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey('failureOnly')) {
            $allLicenseObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
        }
        else {
            $allLicenseObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
        }

        # ESXi Disk Status
        $allDiskObject = New-Object System.Collections.ArrayList
        $jsonInputData = $targetContent.Compute.'ESXi Disk Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey('failureOnly')) {
            $allDiskObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
        }
        else {
            $allDiskObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey('html')) {
            if ($allOverallHealthObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $allOverallHealthObject = $allOverallHealthObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-overall"></a><h3>ESXi Overall Health Status</h3>' -PostContent '<p>No issues found.</p>' 
            } else {
                $allOverallHealthObject = $allOverallHealthObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-overall"></a><h3>ESXi Overall Health Status</h3>' -As Table
            }
            $allOverallHealthObject = Convert-CssClass -htmldata $allOverallHealthObject
            $allOverallHealthObject

            if ($allCoreDumpObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $allCoreDumpObject = $allCoreDumpObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-coredump"></a><h3>ESXi Core Dump Health Status</h3>' -PostContent '<p>No issues found.</p>' 
            } else {
                $allCoreDumpObject = $allCoreDumpObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-coredump"></a><h3>ESXi Core Dump Health Status</h3>' -As Table
            }
            $allCoreDumpObject = Convert-CssClass -htmldata $allCoreDumpObject
            $allCoreDumpObject

            if ($allLicenseObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $allLicenseObject = $allLicenseObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-license"></a><h3>ESXi License Health Status</h3>' -PostContent '<p>No issues found.</p>' 
            } else {
                $allLicenseObject = $allLicenseObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-license"></a><h3>ESXi License Health Status</h3>' -As Table
            }
            $allLicenseObject = Convert-CssClass -htmldata $allLicenseObject
            $allLicenseObject

            if ($allDiskObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $allDiskObject = $allDiskObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-disk"></a><h3>ESXi Disk Health Status</h3>' -PostContent '<p>No issues found.</p>' 
            } else {
                $allDiskObject = $allDiskObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-disk"></a><h3>ESXi Disk Health Status</h3>' -As Table
            }
            $allDiskObject = Convert-CssClass -htmldata $allDiskObject
            $allDiskObject
        }
        else {
            $allOverallDumpObject | Sort-Object Component, Resource
            $allCoreDumpObject | Sort-Object Component, Resource
            $allLicenseObject | Sort-Object Component, Resource
            $allDiskObject | Sort-Object Component, Resource
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-EsxiHealth

Function Publish-NsxtHealth {
    <#
        .SYNOPSIS
        Formats the NSX Health data from the SoS JSON output.

        .DESCRIPTION
        The Publish-NsxtHealth cmdlet formats the NSX Health data from the SoS JSON output and publishes it as
        either a standard PowerShell object or an HTML object. 

        .EXAMPLE
        Publish-NsxtHealth -json <file-name>
        This example extracts and formats the NSX Health data as a PowerShell object from the JSON file.

        .EXAMPLE
        Publish-NsxtHealth -json <file-name> -html
        This example extracts and formats the NSX Health data as an HTML object from the JSON file.

        .EXAMPLE
        Publish-NsxtHealth -json <file-name> -failureOnly
        This example extracts and formats the NSX Health data as a PowerShell object from the JSON file for only the failed items.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$json,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (!(Test-Path -Path $json)) {
            Write-Error "Unable to find JSON file at location ($json)" -ErrorAction Stop
        }
        else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }

        $customObject = New-Object System.Collections.ArrayList
    
        # NSX Manager Health
        $component = 'NSX Manager'
        $inputData = $targetContent.General.'NSX Health'.'NSX Manager'
        foreach ($element in $inputData.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component
            $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue ($element.area -Split (':'))[-1].Trim()
            $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $element.alert
            $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $element.message
            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                if (($element.status -eq 'FAILED')) {
                    $customObject += $elementObject
                }
            }
            else {
                $customObject += $elementObject
            }
        }

        # NSX Container Cluster Health Status
        $component = 'NSX Container Cluster'
        $inputData = $targetContent.General.'NSX Health'.'NSX Container Cluster Health Status'
        foreach ($element in $inputData.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component
            $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue ($element.area -Split (':'))[-1].Trim()
            $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $element.alert
            $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $element.message
            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                if (($element.status -eq 'FAILED')) {
                    $customObject += $elementObject
                }
            }
            else {
                $customObject += $elementObject
            }
        }
        # NSX Cluster Status
        $component = 'NSX Cluster Status'
        $inputData = $targetContent.General.'NSX Health'.'NSX Cluster Status'
        foreach ($resource in $inputData.PsObject.Properties.Value) {
            foreach ($element in $resource.PsObject.Properties.Value) {
                $elementObject = New-Object -TypeName psobject
                $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component
                $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue ($element.area -Split (':'))[-1].Trim()
                $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $element.alert
                $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $element.message
                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                    if (($element.status -eq 'FAILED')) {
                        $customObject += $elementObject
                    }
                }
                else {
                    $customObject += $elementObject
                }
            }
        }

        # NSX Controllers Health
        $component = 'NSX Controllers'
        $inputData = $targetContent.General.'NSX Health'.'NSX Controllers'
        foreach ($resource in $inputData.PsObject.Properties.Value) {
            foreach ($element in $resource.PsObject.Properties.Value) {
                $elementObject = New-Object -TypeName psobject
                $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component
                $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue ($element.area -Split (':'))[-1].Trim()
                $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $element.alert
                $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $element.message
                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                    if (($element.status -eq 'FAILED')) {
                        $customObject += $elementObject
                    }
                }
                else {
                    $customObject += $elementObject
                }
            }
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey('html')) {
            if ($customObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $customObject = $customObject | Sort-Object Resource, Component | ConvertTo-Html -Fragment -PreContent '<a id="nsx-local-manager"></a><h3>NSX Manager Health Status</h3>' -PostContent '<p>No issues found.</p>' 
            } else {
                $customObject = $customObject | Sort-Object Resource, Component | ConvertTo-Html -Fragment -PreContent '<a id="nsx-local-manager"></a><h3>NSX Manager Health Status</h3>' -As Table
            }
            $customObject = Convert-CssClass -htmldata $customObject
            $customObject
        }
        else {
            $customObject | Sort-Object Resource, Component 
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-NsxtHealth

Function Publish-NsxtEdgeNodeHealth {
    <#
        .SYNOPSIS
        Formats the NSX Edge Node Health data from the SoS JSON output.

        .DESCRIPTION
        The Publish-NsxtEdgeNodeHealth cmdlet formats the NSX Edge Node Health data from the SoS JSON output and
        publishes it as either a standard PowerShell object or an HTML object. 

        .EXAMPLE
        Publish-NsxtEdgeNodeHealth -json <file-name>
        This example extracts and formats the NSX Edge Node Health data as a PowerShell object from the JSON file.

        .EXAMPLE
        Publish-NsxtEdgeNodeHealth -json <file-name> -html
        This example extracts and formats the NSX Edge Node Health data as an HTML object from the JSON file.

        .EXAMPLE
        Publish-NsxtEdgeNodeHealth -json <file-name> -failureOnly
        This example extracts and formats the NSX Edge Node Health data as a PowerShell object from the JSON file for only the failed items.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$json,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (!(Test-Path -Path $json)) {
            Write-Error "Unable to find JSON file at location ($json)" -ErrorAction Stop
        }
        else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }

        # NSX Edge Node Health
        $customObject = New-Object System.Collections.ArrayList
        $jsonInputData = $targetContent.General.'NSX Health'.'NSX Edge'
        $nsxtClusters = Get-VCFNsxtCluster
        foreach ($nsxtVip in $nsxtClusters.vipFqdn) {
            $jsonInputData.PSObject.Properties.Remove($nsxtVip)
        }
        foreach ($element in $jsonInputData.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue 'NSX Edge'
            $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue ($element.area -Split (':'))[-1].Trim()
            $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $element.alert
            $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue ($element.message -Split ('Following are the individual health stats'))[0]
            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                if (($element.status -eq 'FAILED')) {
                    $customObject += $elementObject
                }
            } else {
                $customObject += $elementObject
            }
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey('html')) { 
            if ($customObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="nsx-edge"></a><h3>NSX Edge Node Health Status</h3>' -PostContent '<p>No issues found.</p>' 
            } else {
                $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="nsx-edge"></a><h3>NSX Edge Node Health Status</h3>' -As Table
            }
            $customObject = Convert-CssClass -htmldata $customObject
            $customObject
        } else {
            $customObject | Sort-Object Component, Resource
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-NsxtEdgeNodeHealth

Function Publish-NsxtEdgeClusterHealth {
    <#
        .SYNOPSIS
        Formats the NSX Edge Cluster Health data from the SoS JSON output.

        .DESCRIPTION
        The Publish-NsxtEdgeClusterHealth cmdlet formats the NSX Edge Cluster Health data from the SoS JSON output and
        publishes it as either a standard PowerShell object or an HTML object. 

        .EXAMPLE
        Publish-NsxtEdgeClusterHealth -json <file-name>
        This example extracts and formats the NSX Edge Cluster Health data as a PowerShell object from the JSON file.

        .EXAMPLE
        Publish-NsxtEdgeClusterHealth -json <file-name> -html
        This example extracts and formats the NSX Edge Cluster Health data as an HTML object from the JSON file.

        .EXAMPLE
        Publish-NsxtEdgeClusterHealth -json <file-name> -failureOnly
        This example extracts and formats the NSX Edge Cluster Health data as a PowerShell object from the JSON file for only the failed items.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$json,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (!(Test-Path -Path $json)) {
            Write-Error "Unable to find JSON file at location ($json)" -ErrorAction Stop
        }
        else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }        

        # NSX Edge Cluster Health
        $customObject = New-Object System.Collections.ArrayList
        $jsonInputData = $targetContent.General.'NSX Health'.'NSX Edge'
        $nsxtEdgeClusters = Get-VCFEdgeCluster
        foreach ($nsxtEdgeNodes in $nsxtEdgeClusters.edgeNodes.hostname) {
            $jsonInputData.PSObject.Properties.Remove($nsxtEdgeNodes)
        }
        foreach ($element in $jsonInputData.PsObject.Properties.Value) {
            foreach ($cluster in $element.PsObject.Properties.Value) {
                $elementObject = New-Object -TypeName psobject
                $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue 'NSX Edge Cluster'
                $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue ($cluster.area -Split (':'))[-1].Trim()
                $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $cluster.alert
                $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $cluster.message
                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                    if (($element.status -eq 'FAILED')) {
                        $customObject += $elementObject
                    }
                } else {
                    $customObject += $elementObject
                }
            }
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey('html')) { 
            if ($customObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="nsx-edge-cluster"></a><h3>NSX Edge Cluster Health Status</h3>' -PostContent '<p>No issues found.</p>' 
            } else {
                $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="nsx-edge-cluster"></a><h3>NSX Edge Cluster Health Status</h3>' -As Table
            }
            $customObject = Convert-CssClass -htmldata $customObject
            $customObject
        } else {
            $customObject | Sort-Object Component, Resource
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-NsxtEdgeClusterHealth

Function Publish-NtpHealth {
    <#
        .SYNOPSIS
        Formats the NTP Health data from the SoS JSON output.

        .DESCRIPTION
        The Publish-NtpHealth cmdlet formats the NTP Health data from the SoS JSON output and publishes it as
        either a standard PowerShell object or an HTML object. 

        .EXAMPLE
        Publish-NtpHealth -json <file-name>
        This example extracts and formats the NTP Health data as a PowerShell object from the JSON file.

        .EXAMPLE
        Publish-NtpHealth -json <file-name> -html
        This example extracts and formats the NTP Health data as an HTML object from the JSON file.

        .EXAMPLE
        Publish-NtpHealth -json <file-name> -failureOnly
        This example extracts and formats the NTP Health data as a PowerShell object from the JSON file for only the failed items.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$json,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (!(Test-Path -Path $json)) {
            Write-Error "Unable to find JSON file at location ($json)" -ErrorAction Stop
        } else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }

        # NTP Health Status
        $jsonInputData = $targetContent.'NTP' # Extract Data from the provided SOS JSON
        $jsonInputData.PSObject.Properties.Remove('ESXi HW Time')
        $jsonInputData.PSObject.Properties.Remove('ESXi Time')

        if ($PsBoundParameters.ContainsKey("failureOnly")) {
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) { 
            if ($outputObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="infra-ntp"></a><h3>NTP Health Status</h3>' -PostContent '<p>No issues found.</p>' 
            } else {
                $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="infra-ntp"></a><h3>NTP Health Status</h3>' -As Table
            }
            $outputObject = Convert-CssClass -htmldata $outputObject
            $outputObject
        } else {
            $outputObject | Sort-Object Component, Resource 
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-NtpHealth

Function Publish-PasswordHealth {
    <#
        .SYNOPSIS
        Formats the Password Health data from the SoS JSON output.

        .DESCRIPTION
        The Publish-PasswordHealth cmdlet formats the Password Health data from the SoS JSON output and publishes it as
        either a standard PowerShell object or an HTML object. 

        .EXAMPLE
        Publish-PasswordHealth -json <file-name>
        This example extracts and formats the Password Health data as a PowerShell object from the JSON file.

        .EXAMPLE
        Publish-PasswordHealth -json <file-name> -html
        This example extracts and formats the Password Health data as an HTML object from the JSON file.

        .EXAMPLE
        Publish-PasswordHealth -json <file-name> -failureOnly
        This example extracts and formats the Password Health data as a PowerShell object from the JSON file for only the failed items.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$json,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (!(Test-Path -Path $json)) {
            Write-Error "Unable to find JSON file at location ($json)" -ErrorAction Stop
        } else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }

        # Password Expiry Health
        $jsonInputData = $targetContent.'Password Expiry Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) {
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) { 
            if ($outputObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="security-password"></a><h3>Password Expiry Health Status</h3>' -PostContent '<p>No issues found.</p>' 
            } else {
                $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="security-password"></a><h3>Password Expiry Health Status</h3>' -As Table
            }
            $outputObject = Convert-CssClass -htmldata $outputObject
            $outputObject
        } else {
            $outputObject | Sort-Object Component, Resource 
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-PasswordHealth

Function Publish-ServiceHealth {
    <#
        .SYNOPSIS
        Formats the Service Health data from the SoS JSON output.

        .DESCRIPTION
        The Publish-ServiceHealth cmdlet formats the Service Health data from the SoS JSON output and publishes it as
        either a standard PowerShell object or an HTML object. 

        .EXAMPLE
        Publish-ServiceHealth -json <file-name>
        This example extracts and formats the Service Health data as a PowerShell object from the JSON file.

        .EXAMPLE
        Publish-ServiceHealth -json <file-name> -html
        This example extracts and formats the Service Health data as an HTML object from the JSON file.

        .EXAMPLE
        Publish-ServiceHealth -json <file-name> -failureOnly
        This example extracts and formats the Service Health data as a PowerShell object from the JSON file for only the failed items.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$json,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (!(Test-Path -Path $json)) {
            Write-Error "Unable to find JSON file at location ($json)" -ErrorAction Stop
        }
        else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }

        $outputObject = New-Object System.Collections.ArrayList
        $inputData = $targetContent.'Services' # Extract Data from the provided SOS JSON
        foreach ($component in $inputData) {
            foreach ($element in $component.PsObject.Properties.Value) {
                $elementObject = New-Object -TypeName psobject
                $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue ($element.area -Split (':'))[0].Trim()
                $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue ($element.area -Split (':'))[-1].Trim()
                $elementObject | Add-Member -NotePropertyName 'Service Name' -NotePropertyValue $element.title.ToUpper()
                $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $element.alert
                $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $element.message
                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                    if (($element.status -eq 'FAILED')) {
                        $outputObject += $elementObject
                    }
                }
                else {
                    $outputObject += $elementObject
                }
            }
        }

        if ($PsBoundParameters.ContainsKey('html')) { 
            if ($outputObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="general-service"></a><h3>Service Health Status</h3>' -PostContent '<p>No issues found.</p>' 
            } else {
                $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="general-service"></a><h3>Service Health Status</h3>' -As Table
            }
            $outputObject = Convert-CssClass -htmldata $outputObject
            $outputObject
        }
        else {
            $outputObject | Sort-Object Component, Resource 
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-ServiceHealth

Function Publish-VcenterHealth {
    <#
        .SYNOPSIS
        Formats the vCenter Server Health data from the SoS JSON output.

        .DESCRIPTION
        The Publish-VcenterHealth cmdlet formats the vCenter Server Health data from the SoS JSON output and publishes
        it as either a standard PowerShell object or an HTML object. 

        .EXAMPLE
        Publish-VcenterHealth -json <file-name>
        This example extracts and formats the vCenter Server Health data as a PowerShell object from the JSON file.

        .EXAMPLE
        Publish-VcenterHealth -json <file-name> -html
        This example extracts and formats the vCenter Server Health data as an HTML object from the JSON file.

        .EXAMPLE
        Publish-VcenterHealth -json <file-name> -failureOnly
        This example extracts and formats the vCenter Server Health data as a PowerShell object from the JSON file for only the failed items.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$json,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (!(Test-Path -Path $json)) {
            Write-Error "Unable to find JSON file at location ($json)" -ErrorAction Stop
        } else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }

        # vCenter Overall Health
        $jsonInputData = $targetContent.Compute.'vCenter Overall Health' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey('failureOnly')) {
            $vcenterOverall = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
        } else {
            $vcenterOverall = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
        }

        # Ring Topology Health
        $ringTopologyHealth = New-Object System.Collections.ArrayList
        $jsonInputData = $targetContent.General.'Vcenter Ring Topology Status'.'Vcenter Ring Topology Status' # Extract Data from the provided SOS JSON
        $elementObject = New-Object -TypeName psobject
        $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue ($jsonInputData.area -SPlit  ("SDDC:"))[-1].Trim()
        $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $jsonInputData.alert
        $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $jsonInputData.message
        if ($PsBoundParameters.ContainsKey("failureOnly")) {
            if (($jsonInputData.status -eq "FAILED")) {
                $ringTopologyHealth += $elementObject
            }
        } else {
            $ringTopologyHealth += $elementObject
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) { 
            if ($vcenterOverall.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $vcenterOverall = $vcenterOverall | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="vcenter-overall"></a><h3>vCenter Server Overall Health Status</h3>' -PostContent '<p>No issues found.</p>' 
            } else {
                $vcenterOverall = $vcenterOverall | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="vcenter-overall"></a><h3>vCenter Server Overall Health Status</h3>' -As Table
            }
            $vcenterOverall = Convert-CssClass -htmldata $vcenterOverall
            $vcenterOverall

            if ($ringTopologyHealth.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $ringTopologyHealth = $ringTopologyHealth | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="vcenter-ring"></a><h3>vCenter Single Sign-On Ring Topology Health Status</h3>' -PostContent '<p>No issues found.</p>' 
            } else {
                $ringTopologyHealth = $ringTopologyHealth | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="vcenter-ring"></a><h3>vCenter Single Sign-On Ring Topology Health Status</h3>' -As Table
            }
            $ringTopologyHealth = Convert-CssClass -htmldata $ringTopologyHealth
            $ringTopologyHealth
        } else {
            $vcenterOverall | Sort-Object Component, Resource
            $ringTopologyHealth | Sort-Object Component, Resource
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-VcenterHealth

Function Publish-VsanHealth {
    <#
        .SYNOPSIS
<<<<<<< HEAD
        Formats the vSAN Health data from the SoS JSON output.
=======
        formats the vSAN Health data from the SoS JSON output.
>>>>>>> 81222ba (Spellcheck)

        .DESCRIPTION
        The Publish-VsanHealth cmdlet formats the vSAN Health data from the SoS JSON output and publishes it as
        either a standard PowerShell object or an HTML object. 

        .EXAMPLE
        Publish-VsanHealth -json <file-name>
        This example extracts and formats the vSAN Health data as a PowerShell object from the JSON file.

        .EXAMPLE
        Publish-VsanHealth -json <file-name> -html
        This example extracts and formats the vSAN Health data as an HTML object from the JSON file.

        .EXAMPLE
        Publish-VsanHealth -json <file-name> -failureOnly
        This example extracts and formats the vSAN Health data as a PowerShell object from the JSON file for only the failed items.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$json,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (!(Test-Path -Path $json)) {
            Write-Error "Unable to find JSON file at location ($json)" -ErrorAction Stop
        } else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }

        $customObject = New-Object System.Collections.ArrayList
        # VSAN Cluster Health Status
        $jsonInputData = $targetContent.VSAN.'Cluster vSAN Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) {
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
        }
        $customObject += $outputObject # Adding individual component to main customObject
        
        # Cluster Disk Status
        $jsonInputData = $targetContent.VSAN.'Cluster Disk Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) {
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
        }
        $customObject += $outputObject # Adding individual component to main customObject

        # Cluster Data Compression Status
        $jsonInputData = $targetContent.VSAN.'Cluster Data Compression Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) {
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
        }
        $customObject += $outputObject # Adding individual component to main customObject

        # Cluster Data Encryption Status
        $jsonInputData = $targetContent.VSAN.'Cluster Data Encryption Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) {
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
        }
        $customObject += $outputObject # Adding individual component to main customObject

        # Cluster Data Deduplication Status
        $jsonInputData = $targetContent.VSAN.'Cluster Data Deduplication Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) {
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
        }
        $customObject += $outputObject # Adding individual component to main customObject

        # Stretched Cluster Status
        $jsonInputData = $targetContent.VSAN.'Stretched Cluster Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) {
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
        }
        $customObject += $outputObject # Adding individual component to main customObject

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) { 
            if ($customObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="vsan-overall"></a><h3>vSAN Overall Health Status</h3>' -PostContent '<p>No issues found.</p>' 
            } else {
                $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="vsan-overall"></a><h3>vSAN Overall Health Status</h3>' -As Table
            }
            $customObject = Convert-CssClass -htmldata $customObject
            $customObject
        } else {
            $customObject | Sort-Object Component, Resource 
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-VsanHealth

<<<<<<< HEAD
<<<<<<< HEAD
Function Publish-VsanStoragePolicy {
    <#
        .SYNOPSIS
        Formats the vSAN Storage Policy for virtual machines from the SoS JSON output.

        .DESCRIPTION
        The Publish-VsanStoragePolicy cmdlet formats the vSAN Storage Policy data from the SoS JSON output and
        publishes it as either a standard PowerShell object or an HTML object. 

        .EXAMPLE
        Publish-VsanHealth -json <file-name>
        This example extracts and formats the vSAN Storage Policy data as a PowerShell object from the JSON file.

        .EXAMPLE
        Publish-VsanHealth -json <file-name> -html
        This example extracts and formats the vSAN Storage Policy data as an HTML object from the JSON file.

        .EXAMPLE
        Publish-VsanHealth -json <file-name> -failureOnly
        This example extracts and formats the vSAN Storage Policy data as a PowerShell object from the JSON file for only the failed items.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$json,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (!(Test-Path -Path $json)) {
            Write-Error "Unable to find JSON file at location ($json)" -ErrorAction Stop
        } else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }

        # VSAN Storage Policy
        $jsonInputData = $targetContent.vSAN # Extract Data from the provided SOS JSON
        $jsonInputData.PSObject.Properties.Remove('Host vSAN Status')
        $jsonInputData.PSObject.Properties.Remove('Host Disk Status')
        $jsonInputData.PSObject.Properties.Remove('vCenter HCL Status')
        $jsonInputData.PSObject.Properties.Remove('Cluster Data Compression Status')
        $jsonInputData.PSObject.Properties.Remove('Cluster Data Encryption Status')
        $jsonInputData.PSObject.Properties.Remove('Cluster Data Deduplication Status')
        $jsonInputData.PSObject.Properties.Remove('Stretched Cluster Status')
        $jsonInputData.PSObject.Properties.Remove('Stretched Cluster Health Status')
        $jsonInputData.PSObject.Properties.Remove('Stretched Cluster Tests')

        $outputObject = New-Object System.Collections.ArrayList
        foreach ($element in $jsonInputData.PsObject.Properties.Value) { 
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue "Virtual Machine"
            $elementObject | Add-Member -NotePropertyName 'vCenter Server' -NotePropertyValue (($element.area -Split (' : '))[-1] -Split (' VM '))[0].Trim()
            $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue ($element.Message -Split (" "),2)[0].Trim()
            $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $element.alert
            $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue ($element.Message -Split (" "),2)[-1].Trim()
            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                if (($element.status -eq 'FAILED')) {
                    $outputObject += $elementObject
                }
            }
            else {
                $outputObject += $elementObject
            }
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) {
            if ($outputObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $outputObject = $outputObject | Sort-Object Component, 'vCenter Server', Resource | ConvertTo-Html -Fragment -PreContent '<a id="vsan-spbm"></a><h3>vSAN Storage Policy Health Status</h3>' -PostContent '<p>No issues found.</p>' 
            } else {
                $outputObject = $outputObject | Sort-Object Component, 'vCenter Server', Resource | ConvertTo-Html -Fragment -PreContent '<a id="vsan-spbm"></a><h3>vSAN Storage Policy Health Status</h3>' -As Table
            }
            $outputObject = Convert-CssClass -htmldata $outputObject
            $outputObject
        } else {
<<<<<<< HEAD
            $outputObject | Sort-Object Component, vCenter, Resource 
=======
Function Request-SddcManagerStorageHealth {
    <#
		.SYNOPSIS
        Checks the storage health (capacity) in an SDDC Manager appliance.

        .DESCRIPTION
        The Request-SddcManagerStorageHealth cmdlet checks the disk free space in the SDDC Manager
        appliance not reported in the SoS Health Check. The cmdlet connects to SDDC Manager using the -server, -user,
        and password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the Management Domain vCenter Server instance
        - Performs checks on the local storage used space and outputs the results

        .EXAMPLE
        Request-SddcManagerStorageHealth -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -rootPass VMw@re1!
        This example checks the hard disk space in the SDDC Manager appliance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$rootPass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html
    )
    
    # Define thresholds Green < Yellow < Red
    $greenThreshold = 10
    $redThreshold = 20

    Try {
        # Get information from SDDC Manager and format it
        $customObject = New-Object System.Collections.ArrayList
        $command = 'df -h | grep -e "^/" | grep -v "/dev/loop"'
        $output = Invoke-SddcCommand -server $server -user $user -pass $pass -rootPass $rootPass -command $command
        $formatOutput = ($output.ScriptOutput -split '\r?\n').Trim() -replace '(^\s+|\s+$)', '' -replace '\s+', ' '
        foreach ($partition in $formatOutput) {
            $usage = $partition.Split(" ")[4]
            # Make sure that only rows with calculated usage will be included
            if ( !$usage ) { continue }

            # Get the usage percentage as numeric value
            $usage = $usage.Substring(0, $usage.Length - 1)
            $usage = [int]$usage

            # Applying thresholds and creating collection from input
            switch ($usage) {
                { $_ -le $greenThreshold } { # Green if $usage is up to $greenThreshold
                    $alert = 'GREEN'
                    $message = "Used space is less than $greenThreshold%. You could continue with the upgrade."
                }
                { $_ -ge $redThreshold } { # Red if $usage is equal or above $redThreshold
                    $alert = 'RED'
                    $message = "Used space is above $redThreshold%. Please reclaim space on the partition before proceeding further."
                    # TODO Find how to display the message in html on multiple rows (Add <br> with the right escape chars)
                    # In order to display usage, you could run as root in SDDC Manager 'du -Sh <mount-point> | sort -rh | head -10' "
                    # As an alternative you could run PowerCLI commandlet:
                    # 'Invoke-SddcCommand -server <SDDC_Manager_FQDN> -user <administrator@vsphere.local> -pass <administrator@vsphere.local_password> -rootPass <SDDC_Manager_RootPassword> -command "du -Sh <mount-point> | sort -rh | head -10" '
                }
                Default { # Yellow if above two are not matched
                    # TODO - same as above - add hints on new lines }
                    $alert = 'YELLOW'
                    $message = "Used space is between $greenThreshold% and $redThreshold%. Please consider reclaiming some space. "
                }
            }
                                    
            $userObject = New-Object -TypeName psobject
            $userObject | Add-Member -notepropertyname 'Filesystem' -notepropertyvalue $partition.Split(" ")[0]
            $userObject | Add-Member -notepropertyname 'Size' -notepropertyvalue $partition.Split(" ")[1]
            $userObject | Add-Member -notepropertyname 'Available' -notepropertyvalue $partition.Split(" ")[2]
            $userObject | Add-Member -notepropertyname 'Used %' -notepropertyvalue $partition.Split(" ")[4]
            $userObject | Add-Member -notepropertyname 'Mounted on' -notepropertyvalue $partition.Split(" ")[5]
            $userObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $alert
            $userObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $message
            $customObject += $userObject # Creating collection to work with afterwords
>>>>>>> d82c5c1 (Introduce "Request-SddcManagerStorageHealth")
=======
            $outputObject | Sort-Object Component, 'vCenter Server', Resource 
>>>>>>> 6880eb5 (Updated Publish-VsanStoragePolicy)
        }
    }
    Catch {
        Debug-CatchWriter -object $_
<<<<<<< HEAD
    }
}
Export-ModuleMember -Function Publish-VsanStoragePolicy
=======
    }                        
                        
    # Return the structured data to the console or format using HTML CSS Styles
    if ($PsBoundParameters.ContainsKey("html")) { 
        $customObject = $customObject | ConvertTo-Html -Fragment -PreContent "<h2>SDDC Manager Disk Health Status</h2>" -As Table
        $customObject = Convert-AlertClass -htmldata $customObject
    }
    # Return $customObject in HTML or pain format
    $customObject
    
}
Export-ModuleMember -Function Request-SddcManagerStorageHealth
>>>>>>> d82c5c1 (Introduce "Request-SddcManagerStorageHealth")

=======
>>>>>>> 3ef0b04 (Move function to the right place)
##########################################  E N D   O F   F U N C T I O N S  ##########################################
#######################################################################################################################


#######################################################################################################################
####################################  H E A L T H   C H E C K   F U N C T I O N S   ###################################

Function Publish-BackupStatus {
    <#
		.SYNOPSIS
        Request and publish the backup status.

        .DESCRIPTION
        The Publish-BackupStatus cmdlet checks the backup status for SDDC Manager, vCenter Server instances, and NSX
        Local Manager clusters in a VMware Cloud Foundation instance and prepares the data to be published to an HTML
        report. The cmdlet connects to SDDC Manager using the -server, -user, and password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Performs checks on the backup status and outputs the results

        .EXAMPLE
        Publish-BackupStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will publish the backup status for the SDDC Manager, vCenter Server instances, and NSX Local Manager clusters in a VMware Cloud Foundation instance.

        .EXAMPLE
        Publish-BackupStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -failureOnly
        This example will publish the backup status for the SDDC Manager, vCenter Server instances, and NSX Local Manager clusters in a VMware Cloud Foundation instance but only reports issues.

        .EXAMPLE
        Publish-BackupStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will publish the backup status for the vCenter Server instances, and NSX Local Manager clusters in Workload Domain sfo-w01.  
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $allWorkloadDomains = Get-VCFWorkloadDomain
                $singleWorkloadDomain = Get-VCFWorkloadDomain | Where-Object {$_.name -eq $workloadDomain}
                $allBackupStatusObject = New-Object System.Collections.ArrayList

                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                    if ($PsBoundParameters.ContainsKey("allDomains")) {
                        $sddcManagerBackupStatus = Request-SddcManagerBackupStatus -server $server -user $user -pass $pass -failureOnly; $allBackupStatusObject += $sddcManagerBackupStatus
                        foreach ($domain in $allWorkloadDomains ) {
                            $vcenterBackupStatus = Request-vCenterBackupStatus -server $server -user $user -pass $pass -domain $domain.name -failureOnly; $allBackupStatusObject += $vcenterBackupStatus
                            $nsxtManagerBackupStatus = Request-NsxtManagerBackupStatus -server $server -user $user -pass $pass -domain $domain.name -failureOnly; $allBackupStatusObject += $nsxtManagerBackupStatus
                        }
                    } else {
                        if ($singleWorkloadDomain.type -eq "MANAGEMENT") {
                            $sddcManagerBackupStatus = Request-SddcManagerBackupStatus -server $server -user $user -pass $pass -failureOnly; $allBackupStatusObject += $sddcManagerBackupStatus
                        }
                        $vcenterBackupStatus = Request-vCenterBackupStatus -server $server -user $user -pass $pass -domain $domain.name -failureOnly; $allBackupStatusObject += $vcenterBackupStatus
                        $nsxtManagerBackupStatus = Request-NsxtManagerBackupStatus -server $server -user $user -pass $pass -domain $domain.name -failureOnly; $allBackupStatusObject += $nsxtManagerBackupStatus
                    }
                } else {
                    if ($PsBoundParameters.ContainsKey("allDomains")) { 
                        $sddcManagerBackupStatus = Request-SddcManagerBackupStatus -server $server -user $user -pass $pass; $allBackupStatusObject += $sddcManagerBackupStatus
                        foreach ($domain in $allWorkloadDomains ) {
                            $vcenterBackupStatus = Request-vCenterBackupStatus -server $server -user $user -pass $pass -domain $domain.name; $allBackupStatusObject += $vcenterBackupStatus
                            $nsxtManagerBackupStatus = Request-NsxtManagerBackupStatus -server $server -user $user -pass $pass -domain $domain.name; $allBackupStatusObject += $nsxtManagerBackupStatus
                        }
                    } else {
                        if ($singleWorkloadDomain.type -eq "MANAGEMENT") {
                            $sddcManagerBackupStatus = Request-SddcManagerBackupStatus -server $server -user $user -pass $pass; $allBackupStatusObject += $sddcManagerBackupStatus
                        }
                        $vcenterBackupStatus = Request-VcenterBackupStatus -server $server -user $user -pass $pass -domain $workloadDomain; $allBackupStatusObject += $vcenterBackupStatus
                        $nsxtManagerBackupStatus = Request-NsxtManagerBackupStatus -server $server -user $user -pass $pass -domain $workloadDomain; $allBackupStatusObject += $nsxtManagerBackupStatus
                    }
                }

                if ($allBackupStatusObject.Count -eq 0) { $addNoIssues = $true }
                    if ($addNoIssues) {
                        $allBackupStatusObject = $allBackupStatusObject | Sort-Object Component, Resource, Element | ConvertTo-Html -Fragment -PreContent '<a id="infra-backup"></a><h3>Backups Status</h3>' -PostContent "<p>No I=issues Found</p>" 
                    } else {
                        $allBackupStatusObject = $allBackupStatusObject | Sort-Object Component, Resource, Element | ConvertTo-Html -Fragment -PreContent '<a id="infra-backup"></a><h3>Backups Status</h3>' -As Table
                    }
                $allBackupStatusObject = Convert-CssClass -htmldata $allBackupStatusObject
                $allBackupStatusObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-BackupStatus

Function Publish-NsxtTransportNodeStatus {
    <#
		.SYNOPSIS
        Request and publish the status of NSX transport nodes managed by an NSX Manager cluster.

        .DESCRIPTION
        The Publish-NsxtTransportNodeStatus cmdlet checks the status NSX transport nodes managed by an NSX Manager cluster
        and prepares the data to be published to an HTML report.  The cmdlet connects to SDDC Manager using the
        -server, -user, and password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Performs checks on the NSX transport node status and outputs the results

        .EXAMPLE
        Publish-NsxtTransportNodeStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will publish the status of all NSX transport nodes in a VMware Cloud Foundation instance.

        .EXAMPLE
        Publish-NsxtTransportNodeStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -failureOnly
        This example will publish thestatus of all NSX transport nodes in a VMware Cloud Foundation instance but only reports issues.

        .EXAMPLE
        Publish-NsxtTransportNodeStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will publish the BGP status for the NSX transport nodes in a VMware Cloud Foundation instance for a workload domain named sfo-w01.
    #>
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $allWorkloadDomains = Get-VCFWorkloadDomain
                $allNsxtTransportNodeStatusObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                    if ($PsBoundParameters.ContainsKey('allDomains')) {
                        foreach ($domain in $allWorkloadDomains ) {
                            $nsxtTransportNodeStatus = Request-NsxtTransportNodeStatus -server $server -user $user -pass $pass -domain $domain.name -failureOnly; $allNsxtTransportNodeStatusObject += $nsxtTransportNodeStatus
                        }
                    }
                    else {
                        $nsxtTransportNodeStatus = Request-NsxtTransportNodeStatus -server $server -user $user -pass $pass -domain $domain.name -failureOnly; $allNsxtTransportNodeStatusObject += $nsxtTransportNodeStatus
                    }
                }
                else {
                    if ($PsBoundParameters.ContainsKey('allDomains')) { 
                        foreach ($domain in $allWorkloadDomains ) {
                            $nsxtTransportNodeStatus = Request-NsxtTransportNodeStatus -server $server -user $user -pass $pass -domain $domain.name; $allNsxtTransportNodeStatusObject += $nsxtTransportNodeStatus
                        }
                    }
                    else {
                        $nsxtTransportNodeStatus = Request-NsxtTransportNodeStatus -server $server -user $user -pass $pass -domain $workloadDomain; $allNsxtTransportNodeStatusObject += $nsxtTransportNodeStatus
                    }
                }

                if ($allNsxtTransportNodeStatusObject.Count -eq 0) {
                    $addNoIssues = $true 
                }
                if ($addNoIssues) {
                    $allNsxtTransportNodeStatusObject = $allNsxtTransportNodeStatusObject | Sort-Object Domain, Resource, Element | ConvertTo-Html -Fragment -PreContent '<a id="nsx-tn"></a><h3>NSX Transport Node Status</h3>' -PostContent '<p>No issues found.</p>' 
                }
                else {
                    $allNsxtTransportNodeStatusObject = $allNsxtTransportNodeStatusObject | Sort-Object Domain, Resource, Element  | ConvertTo-Html -Fragment -PreContent '<a id="nsx-tn"></a><h3>NSX Transport Node Status</h3>' -As Table
                }
                $allNsxtTransportNodeStatusObject = Convert-CssClass -htmldata $allNsxtTransportNodeStatusObject
                $allNsxtTransportNodeStatusObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-NsxtTransportNodeStatus

Function Publish-NsxtTier0BgpStatus {
    <#
		.SYNOPSIS
        Request and publish the BGP status for the NSX Tier-0 gateways.

        .DESCRIPTION
        The Publish-NsxtTier0BgpStatus cmdlet checks the BGP status for the NSX Tier-0 gateways in a VMware Cloud
        Foundation instance and prepares the data to be published to an HTML report.  The cmdlet connects to SDDC
        Manager using the -server, -user, and password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Performs checks on the BGP status and outputs the results

        .EXAMPLE
        Publish-NsxtTier0BgpStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will publish the BGP status for all NSX Tier-0 gateways in a VMware Cloud Foundation instance.

        .EXAMPLE
        Publish-NsxtTier0BgpStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -failureOnly
        This example will publish the BGP status for all NSX Tier-0 gateways in a VMware Cloud Foundation instance but only for the failed items.

        .EXAMPLE
        Publish-NsxtTier0BgpStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will publish the BGP status for the NSX Tier-0 gateways in a VMware Cloud Foundation instance for a workload domain names sfo-w01.
    #>
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $allWorkloadDomains = Get-VCFWorkloadDomain
                $allNsxtTier0BgpStatusObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                    if ($PsBoundParameters.ContainsKey('allDomains')) {
                        foreach ($domain in $allWorkloadDomains ) {
                            $nsxtTier0BgpStatus = Request-NsxtTier0BgpStatus -server $server -user $user -pass $pass -domain $domain.name -failureOnly; $allNsxtTier0BgpStatusObject += $nsxtTier0BgpStatus
                        }
                    } else {
                        $nsxtTier0BgpStatus = Request-NsxtTier0BgpStatus -server $server -user $user -pass $pass -domain $domain.name -failureOnly; $allNsxtTier0BgpStatusObject += $nsxtTier0BgpStatus
                    }
                } else {
                    if ($PsBoundParameters.ContainsKey('allDomains')) { 
                        foreach ($domain in $allWorkloadDomains ) {
                            $nsxtTier0BgpStatus = Request-NsxtTier0BgpStatus -server $server -user $user -pass $pass -domain $domain.name; $allNsxtTier0BgpStatusObject += $nsxtTier0BgpStatus
                        }
                    } else {
                        $nsxtTier0BgpStatus = Request-NsxtTier0BgpStatus -server $server -user $user -pass $pass -domain $workloadDomain; $allNsxtTier0BgpStatusObject += $nsxtTier0BgpStatus
                    }
                }

                if ($allNsxtTier0BgpStatusObject.Count -eq 0) {
                    $addNoIssues = $true 
                }
                if ($addNoIssues) {
                    $allNsxtTier0BgpStatusObject = $allNsxtTier0BgpStatusObject | Sort-Object 'NSX Manager', 'Domain', 'Tier-0 ID', 'Source Address' | ConvertTo-Html -Fragment -PreContent '<a id="nsx-t0-bgp"></a><h3>NSX Tier-0 Gateway BGP Status</h3>' -PostContent '<p>No issues found.</p>' 
                } else {
                    $allNsxtTier0BgpStatusObject = $allNsxtTier0BgpStatusObject | Sort-Object 'NSX Manager', 'Domain', 'Tier-0 ID', 'Source Address' | ConvertTo-Html -Fragment -PreContent '<a id="nsx-t0-bgp"></a><h3>NSX Tier-0 Gateway BGP Status</h3>' -As Table
                }
                $allNsxtTier0BgpStatusObject = Convert-CssClass -htmldata $allNsxtTier0BgpStatusObject
                $allNsxtTier0BgpStatusObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-NsxtTier0BgpStatus

Function Publish-SnapshotStatus {
    <#
		.SYNOPSIS
        Request and publish the snapshot status for the SDDC Manager, vCenter Server instances, and NSX Edge nodes
        managed by SDDC Manager.

        .DESCRIPTION
        The Publish-SnapshotStatus cmdlet checks the snapshot status for SDDC Manager, vCenter Server instances,
        and NSX Edge nodes in a VMware Cloud Foundation instance and prepares the data to be published
        to an HTML report. The cmdlet connects to SDDC Manager using the -server, -user, and password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Performs checks on the snapshot status and outputs the results

        .NOTES
        The cmdlet will not publish the snapshot status for NSX Local Manager cluster appliances managed by SDDC Manager.
        Snapshots are not recommended for NSX Manager cluster appliances and are disabled by default.

        .EXAMPLE
        Publish-SnapshotStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will publish the snapshot status for the SDDC Manager, vCenter Server instances, and NSX Edge nodes managed by SDDC Manager.  

        .EXAMPLE
        Publish-SnapshotStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -failureOnly
        This example will publish the snapshot status for the SDDC Manager, vCenter Server instances, and NSX Edge nodes managed by SDDC Manager but only failed items

        .EXAMPLE
        Publish-SnapshotStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will publish the snapshot status for the SDDC Manager, vCenter Server instance, and NSX Edge nodes managed by SDDC Manager for a workload domain names sfo-w01.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $allSnapshotStatusObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                    if ($PsBoundParameters.ContainsKey('allDomains')) {
                        $sddcManagerSnapshotStatus = Request-SddcManagerSnapshotStatus -server $server -user $user -pass $pass -failureOnly; $allSnapshotStatusObject += $sddcManagerSnapshotStatus
                        $vcenterSnapshotStatus = Request-VcenterSnapshotStatus -server $server -user $user -pass $pass -allDomains -failureOnly; $allSnapshotStatusObject += $vcenterSnapshotStatus
                        $nsxtEdgeSnapshotStatus = Request-NsxtEdgeSnapshotStatus -server $server -user $user -pass $pass -allDomains -failureOnly; $allSnapshotStatusObject += $nsxtEdgeSnapshotStatus
                    } else {
                        $sddcManagerSnapshotStatus = Request-SddcManagerSnapshotStatus -server $server -user $user -pass $pass -failureOnly; $allSnapshotStatusObject += $sddcManagerSnapshotStatus
                        $vcenterSnapshotStatus = Request-VcenterSnapshotStatus -server $server -user $user -pass $pass -workloadDomain $workloadDomain -failureOnly; $allSnapshotStatusObject += $vcenterBackupStatus
                        $nsxtEdgeSnapshotStatus = Request-NsxtEdgeSnapshotStatus -server $server -user $user -pass $pass -workloadDomain $workloadDomain -failureOnly; $allSnapshotStatusObject += $nsxtEdgeSnapshotStatus
                    }
                } else {
                    if ($PsBoundParameters.ContainsKey('allDomains')) { 
                        $sddcManagerSnapshotStatus = Request-SddcManagerSnapshotStatus -server $server -user $user -pass $pass; $allSnapshotStatusObject += $sddcManagerSnapshotStatus
                        $vcenterSnapshotStatus = Request-VcenterSnapshotStatus -server $server -user $user -pass $pass -allDomains; $allSnapshotStatusObject += $vcenterSnapshotStatus
                        $nsxtEdgeSnapshotStatus = Request-NsxtEdgeSnapshotStatus -server $server -user $user -pass $pass -allDomains; $allSnapshotStatusObject += $nsxtEdgeSnapshotStatus
                    } else {
                        $sddcManagerSnapshotStatus = Request-SddcManagerSnapshotStatus -server $server -user $user -pass $pass; $allSnapshotStatusObject += $sddcManagerSnapshotStatus
                        $vcenterSnapshotStatus = Request-VcenterSnapshotStatus -server $server -user $user -pass $pass -workloadDomain $workloadDomain; $allSnapshotStatusObject += $vcenterSnapshotStatus
                        $nsxtEdgeSnapshotStatus = Request-NsxtEdgeSnapshotStatus -server $server -user $user -pass $pass -workloadDomain $workloadDomain; $allSnapshotStatusObject += $nsxtEdgeSnapshotStatus
                    }
                }

                if ($allSnapshotStatusObject.Count -eq 0) {
                    $addNoIssues = $true 
                }
                if ($addNoIssues) {
                    $allSnapshotStatusObject = $allSnapshotStatusObject | Sort-Object Component, Resource, Element | ConvertTo-Html -Fragment -PreContent '<a id="infra-snapshot"></a><h3>Snapshot Status</h3>' -PostContent '<p>No issues found.</p>' 
                }
                else {
                    $allSnapshotStatusObject = $allSnapshotStatusObject | Sort-Object Component, Resource, Element | ConvertTo-Html -Fragment -PreContent '<a id="infra-snapshot"></a><h3>Snapshot Status</h3><p>By default, snapshots for NSX Local Manager cluster appliances are disabled and are not recommended.</p>' -As Table
                }
                $allSnapshotStatusObject = Convert-CssClass -htmldata $allSnapshotStatusObject
                $allSnapshotStatusObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-SnapshotStatus

Function Publish-LocalUserExpiry {
    <#
		.SYNOPSIS
        Request and publish Local User Expiry

        .DESCRIPTION
        The Publish-LocalUserExpiry cmdlet checks the expiry for local users across the VMware Cloud Foundation
        instance and prepares the data to be published to an HTML report. The cmdlet connects to SDDC Manager using the
        -server, -user, and password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Performs checks on the local OS users and outputs the results

        .EXAMPLE
        Publish-LocalUserExpiry -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -sddcRootPass VMw@re1! -allDomains
        This example checks the expiry for local OS users for all Workload Domains across the VMware Cloud Foundation instance.

        .EXAMPLE
        Publish-LocalUserExpiry -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -sddcRootPass VMw@re1! -workloadDomain sfo-w01
        This example checks the expiry for local OS users for a single Workload Domain in a VMware Cloud Foundation instance.

        .EXAMPLE
        Publish-LocalUserExpiry -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -sddcRootPass VMw@re1! -allDomains -failureOnly
        This example checks the expiry for local OS users for all Workload Domains across the VMware Cloud Foundation instance but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcRootPass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        $allPasswordExpiryObject = New-Object System.Collections.ArrayList
        $allWorkloadDomains = Get-VCFWorkloadDomain
        $singleWorkloadDomain = Get-VCFWorkloadDomain | Where-Object {$_.name -eq $workloadDomain}
        if ($PsBoundParameters.ContainsKey('failureOnly')) {
            if ($PsBoundParameters.ContainsKey("allDomains")) {
                $sddcPasswordExpiry = Request-SddcManagerUserExpiry -server $server -user $user -pass $pass -rootPass $sddcRootPass -failureOnly; $allPasswordExpiryObject += $sddcPasswordExpiry
                $vrslcmPasswordExpiry = Request-vRslcmUserExpiry -server $server -user $user -pass $pass -failureOnly; $allPasswordExpiryObject += $vrslcmPasswordExpiry
                $vcenterPasswordExpiry = Request-vCenterUserExpiry -server $server -user $user -pass $pass -alldomains -failureOnly; $allPasswordExpiryObject += $vcenterPasswordExpiry
                $allWorkloadDomains = Get-VCFWorkloadDomain
                foreach ($domain in $allWorkloadDomains ) {
                    $nsxtManagerPasswordExpiry = Request-NsxtManagerUserExpiry -server $server -user $user -pass $pass -domain $domain.name -failureOnly; $allPasswordExpiryObject += $nsxtManagerPasswordExpiry
                    $nsxtEdgePasswordExpiry = Request-NsxtEdgeUserExpiry -server $server -user $user -pass $pass -domain $domain.name -failureOnly; $allPasswordExpiryObject += $nsxtEdgePasswordExpiry
                }
            }
            else {
                if ($singleWorkloadDomain.type -eq "MANAGEMENT") {
                    $sddcPasswordExpiry = Request-SddcManagerUserExpiry -server $server -user $user -pass $pass -rootPass $sddcRootPass -failureOnly; $allPasswordExpiryObject += $sddcPasswordExpiry
                    $vrslcmPasswordExpiry = Request-vRslcmUserExpiry -server $server -user $user -pass $pass -failureOnly; $allPasswordExpiryObject += $vrslcmPasswordExpiry
                }
                $vcenterPasswordExpiry = Request-vCenterUserExpiry -server $server -user $user -pass $pass -workloadDomain $workloadDomain -failureOnly; $allPasswordExpiryObject += $vcenterPasswordExpiry
                $nsxtManagerPasswordExpiry = Request-NsxtManagerUserExpiry -server $server -user $user -pass $pass -domain $workloadDomain -failureOnly; $allPasswordExpiryObject += $nsxtManagerPasswordExpiry
                $nsxtEdgePasswordExpiry = Request-NsxtEdgeUserExpiry -server $server -user $user -pass $pass -domain $workloadDomain -failureOnly; $allPasswordExpiryObject += $nsxtEdgePasswordExpiry
            }
        }
        else {
            if ($PsBoundParameters.ContainsKey("allDomains")) {
                $sddcPasswordExpiry = Request-SddcManagerUserExpiry -server $server -user $user -pass $pass -rootPass $sddcRootPass; $allPasswordExpiryObject += $sddcPasswordExpiry
                $vrslcmPasswordExpiry = Request-vRslcmUserExpiry -server $server -user $user -pass $pass; $allPasswordExpiryObject += $vrslcmPasswordExpiry
                $vcenterPasswordExpiry = Request-vCenterUserExpiry -server $server -user $user -pass $pass -alldomains; $allPasswordExpiryObject += $vcenterPasswordExpiry
                $allWorkloadDomains = Get-VCFWorkloadDomain
                foreach ($domain in $allWorkloadDomains ) {
                    $nsxtManagerPasswordExpiry = Request-NsxtManagerUserExpiry -server $server -user $user -pass $pass -domain $domain.name; $allPasswordExpiryObject += $nsxtManagerPasswordExpiry
                    $nsxtEdgePasswordExpiry = Request-NsxtEdgeUserExpiry -server $server -user $user -pass $pass -domain $domain.name; $allPasswordExpiryObject += $nsxtEdgePasswordExpiry
                }
            }
            else {
                if ($singleWorkloadDomain.type -eq "MANAGEMENT") {
                    $sddcPasswordExpiry = Request-SddcManagerUserExpiry -server $server -user $user -pass $pass -rootPass $sddcRootPass; $allPasswordExpiryObject += $sddcPasswordExpiry
                    $vrslcmPasswordExpiry = Request-vRslcmUserExpiry -server $server -user $user -pass $pass; $allPasswordExpiryObject += $vrslcmPasswordExpiry
                }
                $vcenterPasswordExpiry = Request-vCenterUserExpiry -server $server -user $user -pass $pass -workloadDomain $workloadDomain; $allPasswordExpiryObject += $vcenterPasswordExpiry
                $nsxtManagerPasswordExpiry = Request-NsxtManagerUserExpiry -server $server -user $user -pass $pass -domain $workloadDomain; $allPasswordExpiryObject += $nsxtManagerPasswordExpiry
                $nsxtEdgePasswordExpiry = Request-NsxtEdgeUserExpiry -server $server -user $user -pass $pass -domain $workloadDomain; $allPasswordExpiryObject += $nsxtEdgePasswordExpiry
            }
        }

        if ($allPasswordExpiryObject.Count -eq 0) { $addNoIssues = $true }
        if ($addNoIssues) {
            $allPasswordExpiryObject = $allPasswordExpiryObject | Sort-Object Resource, Component | ConvertTo-Html -Fragment -PreContent '<a id="security-password"></a><h3>Password Expiry Health Status</h3>' -PostContent '<p>No issues found.</p>' 
        } else {
            $allPasswordExpiryObject = $allPasswordExpiryObject | Sort-Object Resource, Component | ConvertTo-Html -Fragment -PreContent '<a id="security-password"></a><h3>Password Expiry Health Status</h3>' -As Table
        }
        $allPasswordExpiryObject = Convert-CssClass -htmldata $allPasswordExpiryObject
        $allPasswordExpiryObject
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-LocalUserExpiry

Function Publish-NsxtCombinedHealth {
    <#
		.SYNOPSIS
        Request and publish NSX Manager Health.

        .DESCRIPTION
        The Publish-NsxtCombinedHealth cmdlet checks the health of NSX Manager on the VMware Cloud Foundation instance
        and prepares the data to be published to an HTML report. The cmdlet connects to SDDC Manager using the
        -server, -user, and password values:
        - Validates that network connectivity and autehentication is available to SDDC Manager
        - Validates that network connectivity and autehentication is available to NSX Manager
        - Performs health checks and outputs the results

        .EXAMPLE
        Publish-NsxtCombinedHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -json <json-file> -allDomains
        This example checks NSX Manager health for all Workload Domains across the VMware Cloud Foundation instance.

        .EXAMPLE
        Publish-NsxtCombinedHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -json <json-file> -workloadDomain sfo-w01
        This example checks NSX Manager health for a single Workload Domain in a VMware Cloud Foundation instance.

        .EXAMPLE
        Publish-NsxtCombinedHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -json <json-file> -allDomains -failureOnly
        This example checks NSX Manager health for all Workload Domains across the VMware Cloud Foundation instance but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$json,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        $allNsxtHealthObject = New-Object System.Collections.ArrayList
        $allWorkloadDomains = Get-VCFWorkloadDomain
        if ($PsBoundParameters.ContainsKey("allDomains") -and $PsBoundParameters.ContainsKey("failureOnly")) { 
            foreach ($domain in $allWorkloadDomains ) {
                $nsxtVidmStatus = Request-NsxtVidmStatus -server $server -user $user -pass $pass -domain $domain.name -failureOnly; $allNsxtHealthObject += $nsxtVidmStatus
                $nsxtComputeManagerStatus = Request-NsxtComputeManagerStatus -server $server -user $user -pass $pass -domain $domain.name -failureOnly; $allNsxtHealthObject += $nsxtComputeManagerStatus
            }
            $nsxtHtml = Publish-NsxtHealth -json $jsonFilePath -failureOnly; $allNsxtHealthObject += $nsxtHtml
        } elseif ($PsBoundParameters.ContainsKey("allDomains")) {
            foreach ($domain in $allWorkloadDomains ) {
                $nsxtVidmStatus = Request-NsxtVidmStatus -server $server -user $user -pass $pass -domain $domain.name; $allNsxtHealthObject += $nsxtVidmStatus
                $nsxtComputeManagerStatus = Request-NsxtComputeManagerStatus -server $server -user $user -pass $pass -domain $domain.name; $allNsxtHealthObject += $nsxtComputeManagerStatus
            }
            $nsxtHtml = Publish-NsxtHealth -json $jsonFilePath; $allNsxtHealthObject += $nsxtHtml
        }

        if ($PsBoundParameters.ContainsKey("workloadDomain") -and $PsBoundParameters.ContainsKey("failureOnly")) { 
            $nsxtVidmStatus = Request-NsxtVidmStatus -server $server -user $user -pass $pass -domain $workloadDomain -failureOnly; $allNsxtHealthObject += $nsxtVidmStatus
            $nsxtComputeManagerStatus = Request-NsxtComputeManagerStatus -server $server -user $user -pass $pass -domain $workloadDomain -failureOnly; $allNsxtHealthObject += $nsxtComputeManagerStatus
            $nsxtHtml = Publish-NsxtHealth -json $jsonFilePath -failureOnly; $allNsxtHealthObject += $nsxtHtml
        } elseif ($PsBoundParameters.ContainsKey("workloadDomain")) {
            $nsxtVidmStatus = Request-NsxtVidmStatus -server $server -user $user -pass $pass -domain $workloadDomain; $allNsxtHealthObject += $nsxtVidmStatus
            $nsxtComputeManagerStatus = Request-NsxtComputeManagerStatus -server $server -user $user -pass $pass -domain $workloadDomain; $allNsxtHealthObject += $nsxtComputeManagerStatus
            $nsxtHtml = Publish-NsxtHealth -json $jsonFilePath; $allNsxtHealthObject += $nsxtHtml
        }

        if ($allNsxtHealthObject.Count -eq 0) { $addNoIssues = $true }
        if ($addNoIssues) {
            $allNsxtHealthObject = $allNsxtHealthObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="nsx-local-manager"></a><h3>NSX Manager Health Status</h3>' -PostContent '<p>No issues found.</p>' 
        } else {
            $allNsxtHealthObject = $allNsxtHealthObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="nsx-local-manager"></a><h3>NSX Manager Health Status</h3>' -As Table
        }
        $allNsxtHealthObject = Convert-CssClass -htmldata $allNsxtHealthObject
        $allNsxtHealthObject
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-NsxtCombinedHealth

Function Publish-StorageCapacityHealth {
    <#
		.SYNOPSIS
        Request and publish the storage capacity status.

        .DESCRIPTION
        The Publish-StorageCapacityHealth cmdlet checks the storage usage status for SDDC Manager, vCenter Server, 
        Datastores and ESXi hosts, in a VMware Cloud Foundation instance and prepares the data to be published
        to an HTML report or plain text to console. The cmdlet connects to SDDC Manager using the -server, -user, -password and -rootPass values:
        - Validates the network connectivity and authantication to the SDDC Manager instance
        - Performs checks on the storage usage status and outputs the results

        .EXAMPLE
        Publish-StorageCapacityHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -rootPass VMw@re1! -allDomains
        This example will publish storage usage status for SDDC Manager, vCenter Server instances, ESXi hosts, and datastores in a VMware Cloud Foundation instance  

        .EXAMPLE
        Publish-StorageCapacityHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -rootPass VMw@re1! -allDomains -failureOnly
        This example will publish storage usage status for SDDC Manager, vCenter Server instances, ESXi hosts, and datastores in a VMware Cloud Foundation instance but only for the failed items.

        .EXAMPLE
        Publish-StorageCapacityHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -rootPass VMw@re1! -workloadDomain sfo-w01
        This example will publish storage usage status for a specific Workload Domain in a VMware Cloud Foundation instance
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$rootPass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $allWorkloadDomains = Get-VCFWorkloadDomain
                $singleWorkloadDomain = Get-VCFWorkloadDomain | Where-Object {$_.name -eq $workloadDomain}
                $allStorageCapacityHealth = New-Object System.Collections.ArrayList

                if ($PsBoundParameters.ContainsKey("allDomains")) {
                    if ($PsBoundParameters.ContainsKey("failureOnly")) {
                        $sddcManagerStorageHealth = Request-SddcManagerStorageHealth -server $server -user $user -pass $pass -rootPass $rootPass -failureOnly;
                        foreach ($domain in $allWorkloadDomains ) {
                            $vCenterStorageHealth = Request-VcenterStorageHealth -server $server -user $user -pass $pass -domain $domain.name -failureOnly; $allVcenterStorageHealth += $vCenterStorageHealth
                            $esxiStorageCapacity = Request-EsxiStorageCapacity -server $server -user $user -pass $pass -domain $domain.name -failureOnly; $allEsxiStorageCapacity += $esxiStorageCapacity
                            $datastoreStorageCapacity = Request-DatastoreStorageCapacity -server $server -user $user -pass $pass -domain $domain.name -failureOnly; $allDatastoreStorageCapacity += $datastoreStorageCapacity
                        }
                    } else {
                        $sddcManagerStorageHealth = Request-SddcManagerStorageHealth -server $server -user $user -pass $pass -rootPass $rootPass
                        foreach ($domain in $allWorkloadDomains ) {
                            $vCenterStorageHealth = Request-VcenterStorageHealth -server $server -user $user -pass $pass -domain $domain.name; $allVcenterStorageHealth += $vCenterStorageHealth
                            $esxiStorageCapacity = Request-EsxiStorageCapacity -server $server -user $user -pass $pass -domain $domain.name; $allEsxiStorageCapacity += $esxiStorageCapacity
                            $datastoreStorageCapacity = Request-DatastoreStorageCapacity -server $server -user $user -pass $pass -domain $domain.name; $allDatastoreStorageCapacity += $datastoreStorageCapacity                       
                        }
                    }
                } else {
                    if ($PsBoundParameters.ContainsKey("failureOnly")) {
                        if ($singleWorkloadDomain.type -eq "MANAGEMENT") {
                            $sddcManagerStorageHealth = Request-SddcManagerStorageHealth -server $server -user $user -pass $pass -rootPass $rootPass -failureOnly
                        }
                        $vCenterStorageHealth = Request-VcenterStorageHealth -server $server -user $user -pass $pass -domain $workloadDomain -failureOnly; $allVcenterStorageHealth += $vCenterStorageHealth
                        $esxiStorageCapacity = Request-EsxiStorageCapacity -server $server -user $user -pass $pass -domain $workloadDomain -failureOnly; $allEsxiStorageCapacity += $esxiStorageCapacity
                        $datastoreStorageCapacity = Request-DatastoreStorageCapacity -server $server -user $user -pass $pass -domain $workloadDomain -failureOnly; $allDatastoreStorageCapacity += $datastoreStorageCapacity
                    } else {
                        if ($singleWorkloadDomain.type -eq "MANAGEMENT") {
                            $sddcManagerStorageHealth = Request-SddcManagerStorageHealth -server $server -user $user -pass $pass -rootPass $rootPass
                        }
                        $vCenterStorageHealth = Request-VcenterStorageHealth -server $server -user $user -pass $pass -domain $workloadDomain; $allVcenterStorageHealth += $vCenterStorageHealth 
                        $esxiStorageCapacity = Request-EsxiStorageCapacity -server $server -user $user -pass $pass -domain $workloadDomain; $allEsxiStorageCapacity += $esxiStorageCapacity
                        $datastoreStorageCapacity = Request-DatastoreStorageCapacity -server $server -user $user -pass $pass -domain $workloadDomain; $allDatastoreStorageCapacity += $datastoreStorageCapacity
                    }
                }

                if ($sddcManagerStorageHealth.Count -eq 0) {
                    $addNoIssues = $true 
                }
                if ($addNoIssues) {
                    $sddcManagerStorageHealth = $sddcManagerStorageHealth | ConvertTo-Html -Fragment -PreContent '<a id="storage-sddcmanager"></a><h3>SDDC Manager Disk Health Status</h3>' -PostContent '<p>No Issues Found.</p>'
                }
                else {
                    $sddcManagerStorageHealth = $sddcManagerStorageHealth | ConvertTo-Html -Fragment -PreContent '<a id="storage-sddcmanager"></a><h3>SDDC Manager Disk Health Status</h3>' -As Table
                }
                $sddcManagerStorageHealth = Convert-CssClass -htmldata $sddcManagerStorageHealth

                if ($allVcenterStorageHealth.Count -eq 0) {
                    $addNoIssues = $true 
                }
                if ($addNoIssues) {
                    $allVcenterStorageHealth = $allVcenterStorageHealth | Sort-Object FQDN, Filesystem | ConvertTo-Html -Fragment -PreContent '<a id="storage-vcenter"></a><h3>vCenter Server Disk Health</h3>' -PostContent '<p>No Issues Found.</p>'
                }
                else {
                    $allVcenterStorageHealth = $allVcenterStorageHealth | Sort-Object  FQDN, Filesystem | ConvertTo-Html -Fragment -PreContent '<a id="storage-vcenter"></a><h3>vCenter Server Disk Health</h3>' -As Table
                }
                $allVcenterStorageHealth = Convert-CssClass -htmldata $allVcenterStorageHealth

                if ($allEsxiStorageCapacity.Count -eq 0) {
                    $addNoIssues = $true 
                }
                if ($addNoIssues) {
                    $allEsxiStorageCapacity = $allEsxiStorageCapacity | Sort-Object Domain, 'ESXi FQDN', 'Volume Name' | ConvertTo-Html -Fragment -PreContent '<a id="storage-esxi"></a><h3>ESXi Host Local Volume Capacity</h3>' -PostContent '<p>No Issues Found.</p>'
                }
                else {
                    $allEsxiStorageCapacity = $allEsxiStorageCapacity | Sort-Object Domain, 'ESXi FQDN', 'Volume Name' | ConvertTo-Html -Fragment -PreContent '<a id="storage-esxi"></a><h3>ESXi Host Local Volume Capacity</h3>' -As Table
                }
                $allEsxiStorageCapacity = Convert-CssClass -htmldata $allEsxiStorageCapacity

                if ($allDatastoreStorageCapacity.Count -eq 0) {
                    $addNoIssues = $true 
                }
                if ($addNoIssues) {
                    $allDatastoreStorageCapacity = $allDatastoreStorageCapacity | Sort-Object 'vCenter Server', 'Datastore Name' | ConvertTo-Html -Fragment -PreContent '<a id="storage-datastore"></a><h3>Datastore Space Usage Report</h3>' -PostContent '<p>No Issues Found.</p>'
                }
                else {
                    $allDatastoreStorageCapacity = $allDatastoreStorageCapacity | Sort-Object 'vCenter Server', 'Datastore Name' | ConvertTo-Html -Fragment -PreContent '<a id="storage-datastore"></a><h3>Datastore Space Usage Report</h3>' -As Table
                }
                $allDatastoreStorageCapacity = Convert-CssClass -htmldata $allDatastoreStorageCapacity
                
                $allStorageCapacityHealth += $sddcManagerStorageHealth
                $allStorageCapacityHealth += $allVcenterStorageHealth
                $allStorageCapacityHealth += $allEsxiStorageCapacity
                $allStorageCapacityHealth += $allDatastoreStorageCapacity
                $allStorageCapacityHealth
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-StorageCapacityHealth

Function Request-SddcManagerUserExpiry {
    <#
		.SYNOPSIS
        Checks the expiry for additional local OS users in an SDDC Manager appliance.

        .DESCRIPTION
        The Request-SddcManagerUserExpiry cmdlet checks the expiry for additional local users in the SDDC Manager
        appliance not reported in the SoS Health Check. The cmdlet connects to SDDC Manager using the -server, -user,
        and password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Performs checks on the local OS users in an SDDC Manager instance and outputs the results

        .EXAMPLE
        Request-SddcManagerUserExpiry -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -rootPass VMw@re1!
        This example checks the expiry for all local OS users in the SDDC Manager appliance.

        .EXAMPLE
        Request-SddcManagerUserExpiry -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -rootPass VMw@re1! -failureOnly
        This example checks the expiry for all local OS users in the SDDC Manager appliance but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$rootPass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT)) {
                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            $customObject = New-Object System.Collections.ArrayList
                            $elementObject = Request-LocalUserExpiry -fqdn $server -component SDDC -rootPass $rootPass -checkUser backup
                            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                    $customObject += $elementObject
                                }
                            }
                            else {
                                $customObject += $elementObject
                            }
                            $elementObject = Request-LocalUserExpiry -fqdn $server -component SDDC -rootPass $rootPass -checkUser root
                            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                    $customObject += $elementObject
                                }
                            }
                            else {
                                $customObject += $elementObject
                            }
                            $elementObject = Request-LocalUserExpiry -fqdn $server -component SDDC -rootPass $rootPass -checkUser vcf
                            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                    $customObject += $elementObject
                                }
                            }
                            else {
                                $customObject += $elementObject
                            }
                            $customObject | Sort-Object Component, Resource # Output Results
                        }
                        Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                    }
                }
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-SddcManagerUserExpiry

Function Request-NsxtEdgeUserExpiry {
    <#
        .SYNOPSIS
        Checks the expiry for local OS users in an an NSX Edge node appliance.

        .DESCRIPTION
        The Request-NsxtEdgeUserExpiry cmdlet checks the expiry for additional local OS users for an NSX Edge node.
        The cmdlet connects to SDDC Manager using the -server, -user, and password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Performs checks on the local OS users for NSX Manager appliances and outputs the results

        .EXAMPLE
        Request-NsxtEdgeUserExpiry -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example checks the expiry for local OS users for the NSX Edge node appliances for a specific workload domain.

        .EXAMPLE
        Request-NsxtEdgeUserExpiry -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
        This example checks the expiry for local OS users for the NSX Edge node appliances for a specific workload domain but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain)) {
                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            if (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $domain }) {
                                if (($vcfNsxDetails = Get-NsxtServerDetail -fqdn $server -username $user -password $pass -domain $domain)) {   
                                    if (($vcfNsxEdgeDetails = Get-VCFEdgeCluster | Where-Object { $_.nsxtCluster.vipFQDN -eq $vcfNsxDetails.fqdn })) {   
                                        $customObject = New-Object System.Collections.ArrayList
                                        foreach ($nsxtEdgeNode in $vcfNsxEdgeDetails.edgeNodes) {
                                            $rootPass = (Get-VCFCredential | Where-Object { $_.credentialType -eq 'SSH' -and $_.resource.resourceName -eq $vcfNsxDetails.fqdn }).password
                                            $elementObject = Request-LocalUserExpiry -fqdn $nsxtEdgeNode.hostname -component 'NSX Edge' -rootPass $rootPass -checkUser admin
                                            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                                if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                                    $customObject += $elementObject
                                                }
                                            }
                                            else {
                                                $customObject += $elementObject
                                            }
                                            $elementObject = Request-LocalUserExpiry -fqdn $nsxtEdgeNode.hostname -component 'NSX Edge' -rootPass $rootPass -checkUser audit
                                            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                                if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                                    $customObject += $elementObject
                                                }
                                            }
                                            else {
                                                $customObject += $elementObject
                                            }
                                            $elementObject = Request-LocalUserExpiry -fqdn $nsxtEdgeNode.hostname -component 'NSX Edge' -rootPass $rootPass -checkUser root
                                            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                                if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                                    $customObject += $elementObject
                                                }
                                            }
                                            else {
                                                $customObject += $elementObject
                                            }
                                        }
                                    }
                                    $customObject | Sort-Object Component, Resource # Output Results
                                }
                            }
                        }
                        Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                    }    
                }
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-NsxtEdgeUserExpiry

Function Request-NsxtManagerUserExpiry {
    <#
        .SYNOPSIS
        Checks the expiry for local OS users in an NSX Manager appliance.

        .DESCRIPTION
        The Request-NsxtManagerUserExpiry cmdlet checks the expiry for additional local OS users in the NSX Manager
        cluster appliance. The cmdlet connects to SDDC Manager using the -server, -user, and password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Performs checks on the local OS users for NSX Manager appliances and outputs the results

        .EXAMPLE
        Request-NsxtManagerUserExpiry -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example checks the expiry for local OS users for the NSX Manager appliances for a specific workload domain.

        .EXAMPLE
        Request-NsxtManagerUserExpiry -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
        This example checks the expiry for local OS users for the NSX Manager appliances for a specific workload domain but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT)) {
                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            if (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $domain }) {
                                if (($vcfNsxDetails = Get-NsxtServerDetail -fqdn $server -username $user -password $pass -domain $domain -listNodes)) {    
                                    $customObject = New-Object System.Collections.ArrayList
                                    foreach ($nsxtManagerNode in $vcfNsxDetails.nodes) {
                                        $rootPass = (Get-VCFCredential | Where-Object { $_.credentialType -eq 'SSH' -and $_.resource.resourceName -eq $vcfNsxDetails.fqdn }).password | Select-Object -first 1
                                        $elementObject = Request-LocalUserExpiry -fqdn $nsxtManagerNode.fqdn -component 'NSX Manager' -rootPass $rootPass -checkUser admin
                                        if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                            if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                                $customObject += $elementObject
                                            }
                                        }
                                        else {
                                            $customObject += $elementObject
                                        }
                                        $elementObject = Request-LocalUserExpiry -fqdn $nsxtManagerNode.fqdn -component 'NSX Manager' -rootPass $rootPass -checkUser audit
                                        if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                            if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                                $customObject += $elementObject
                                            }
                                        }
                                        else {
                                            $customObject += $elementObject
                                        }
                                        $elementObject = Request-LocalUserExpiry -fqdn $nsxtManagerNode.fqdn -component 'NSX Manager' -rootPass $rootPass -checkUser root
                                        if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                            if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                                $customObject += $elementObject
                                            }
                                        }
                                        else {
                                            $customObject += $elementObject
                                        }
                                    }
                                    $customObject | Sort-Object Component, Resource # Output Results
                                }
                            }
                        }
                        Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                    }    
                }
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-NsxtManagerUserExpiry

Function Request-vCenterUserExpiry {
    <#
		.SYNOPSIS
        Checks the local OS user expiry in a vCenter Server instance.

        .DESCRIPTION
        The Request-vCenterUserExpiry cmdlets checks the expiry date of local accounts on vCenter Server. The cmdlet 
        connects to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Gathers the details for each vCenter Server
        - Collects information for the local OS 'root' account
        - Checks when the password will expire and outputs the results

        .EXAMPLE
        Request-vCenterUserExpiry -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will check the expiry date of the local OS 'root' account for all vCenter Server instances managed by SDDC Manager.

        .EXAMPLE
        Request-vCenterUserExpiry -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will check the expiry date of the local OS 'root' account for a single workload domain

        .EXAMPLE
        Request-vCenterUserExpiry -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -failureOnly
        This example will check the expiry date of the local OS 'root' account for all vCenter Server instances but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT)) {
                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            $customObject = New-Object System.Collections.ArrayList
                            if ($PsBoundParameters.ContainsKey("allDomains")) { 
                                $allVcenters = Get-VCFvCenter
                                foreach ($vcenter in $allVcenters) {
                                    $rootPass = (Get-VCFCredential | Where-Object {$_.credentialType -eq "SSH" -and $_.resource.resourceName -eq $vcenter.fqdn}).password
                                    $elementObject = Request-LocalUserExpiry -fqdn $vcenter.fqdn -component vCenter -rootPass $rootPass -checkUser root
                                    if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                        if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                            $customObject += $elementObject
                                        }
                                    } else {
                                        $customObject += $elementObject
                                    }
                                }
                            } else {
                                $vcenter = (Get-VCFWorkloadDomain | Where-Object {$_.name -eq $workloadDomain}).vcenters.fqdn
                                $rootPass = (Get-VCFCredential | Where-Object {$_.credentialType -eq "SSH" -and $_.resource.resourceName -eq $vcenter}).password
                                $elementObject = Request-LocalUserExpiry -fqdn $vcenter -component vCenter -rootPass $rootPass -checkUser root
                                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                    if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                        $customObject += $elementObject
                                    }
                                } else {
                                    $customObject += $elementObject
                                }
                            }
                            $customObject | Sort-Object Component, Resource # Output Results
                        }
                        Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                    }
                }
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-vCenterUserExpiry

Function Request-vRslcmUserExpiry {
    <#
		.SYNOPSIS
        Checks the local OS user expiry in the vRealize Suite Lifecycle Manager instance.

        .DESCRIPTION
        The Request-vRslcmUserExpiry cmdlets checks the expiry date of local OS user accounts on vRealize Suite
        Lifecycle Manager. The cmdlet connects to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Gathers the details for vRealize Suite Lifecycle Manager
        - Collects information for the local OS 'root' account
        - Checks when the password will expire and outputs the results

        .EXAMPLE
        Request-vRslcmUserExpiry -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
        This example will check the expiry date of the local OS 'root' account on the vRealize Suite Lifecycle Manager instance deployed by SDDC Manager.

        .EXAMPLE
        Request-vRslcmUserExpiry -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -failureOnly
        This example will check the expiry date of the local OS 'root' account on the vRealize Suite Lifecycle Manager instance but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    if (Test-VCFConnection -server $server) {
        if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT)) {
                if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                    if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                        if (Get-VCFvRSLCM) {
                            $customObject = New-Object System.Collections.ArrayList
                            $vrslcm = Get-VCFvRSLCM
                            $rootPass = (Get-VCFCredential | Where-Object {$_.credentialType -eq "SSH" -and $_.resource.resourceName -eq $vrslcm.fqdn}).password
                            $elementObject = Request-LocalUserExpiry -fqdn $vrslcm.fqdn -component vRSLCM -rootPass $rootPass -checkUser root
                            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                    $customObject += $elementObject
                                }
                            } else {
                                $customObject += $elementObject
                            }
                            $customObject | Sort-Object Component, Resource
                        }
                    }
                    Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                }
            }
        }
    }
}
Export-ModuleMember -Function Request-vRslcmUserExpiry

Function Request-NsxtVidmStatus {
    <#
        .SYNOPSIS
        Returns the status of the Identity Manager integration for an NSX Manager cluster.

        .DESCRIPTION
        The Request-NsxtVidmStatus cmdlet returns the status of the Identity Manager integration for an NSX Manager cluster.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates network connectivity and authentication to the SDDC Manager instanc
        - Gathers the details for the NSX Manager cluster from the SDDC Manager
        - Validates network connectivity and authentication to the NSX Local Manager cluster
        - Collects the Identity Manager integration status details

        .EXAMPLE
        Request-NsxtVidmStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return the status of the Identity Manager integration for an NSX Manager cluster managed by SDDC Manager for a workload domain.

        .EXAMPLE
        Request-NsxtVidmStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
        This example will return the status of the Identity Manager integration for an NSX Manager cluster managed by SDDC Manager for a workload domain but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfNsxDetails = Get-NsxtServerDetail -fqdn $server -username $user -password $pass -domain $domain)) {
                    if (Test-NSXTConnection -server $vcfNsxDetails.fqdn) {
                        if (Test-NSXTAuthentication -server $vcfNsxDetails.fqdn -user $vcfNsxDetails.adminUser -pass $vcfNsxDetails.adminPass) {        
                            $customObject = New-Object System.Collections.ArrayList
                            $component = 'Identity Manager Integration' # Define the component name
                            $resource = $vcfNsxDetails.fqdn # Define the resource name
                            $integration = Get-NsxtVidmStatus

                            # Set the alert and message based on the status of the integration
                            if ($integration.vidm_enable -eq $true) {   
                                $alert = 'GREEN' # Ok; enabled
                                $message = 'Integration is enabled ' # Set the status message
                            } else {
                                $alert = '-' # Notice; not enabled
                                $message = 'Integration is not enabled. ' # Critical; failure
                            }

                            # Set the alert and message based on the status of the runtime state
                            if ($integration.runtime_state -eq 'ALL_OK') {
                                $alert = 'GREEN' # Ok; integration status is OK
                                $messageState = 'and healthy.' # Set the alert message
                            } elseif ($integration.vidm_enable -eq $true -and $integration.runtime_state -ne 'ALL_OK') {
                                $alert = 'RED' # Critical; integration status is has failed
                                $messageBackupAge = 'but unhealthy.' # Set the alert message
                            } elseif ($integration.vidm_enable -eq $false -and $integration.runtime_state -ne 'ALL_OK') {
                                $alert = '-' # Notice; integration is not enabled
                            }

                            $message += $messageState # Combine the alert message

                            # Add the properties to the element object
                            $elementObject = New-Object -TypeName psobject
                            $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component # Set the component name
                            $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $resource # Set the resource name
                            $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert # Set the alert
                            $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue "$message" # Set the message
                            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                    $customObject += $elementObject
                                }
                            }
                            else {
                                $customObject += $elementObject
                            }  
                        }
                        $customObject | Sort-Object Component, Resource
                    }
                }
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-NsxtVidmStatus

Function Request-NsxtComputeManagerStatus {
    <#
        .SYNOPSIS
        Returns the status of the compute managers attached to an NSX Manager cluster.

        .DESCRIPTION
        The Request-NsxtComputeManagerStatus cmdlet returns the status of the compute managers attached to an NSX Manager cluster.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates network connectivity and authentication to the SDDC Manager instanc
        - Gathers the details for the NSX Manager cluster from the SDDC Manager
        - Validates network connectivity and authentication to the NSX Local Manager cluster
        - Collects the status of the compute managers

        .EXAMPLE
        Request-NsxtComputeManagerStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return the status of the compute managers attached to an NSX Manager cluster managed by SDDC Manager for a workload domain.

        .EXAMPLE
        Request-NsxtComputeManagerStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
        This example will return the status of the compute managers attached to an NSX Manager cluster managed by SDDC Manager for a workload domain but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfNsxDetails = Get-NsxtServerDetail -fqdn $server -username $user -password $pass -domain $domain)) {
                    if (Test-NSXTConnection -server $vcfNsxDetails.fqdn) {
                        if (Test-NSXTAuthentication -server $vcfNsxDetails.fqdn -user $vcfNsxDetails.adminUser -pass $vcfNsxDetails.adminPass) {
                            $vcenter = (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $domain }).vcenters.fqdn
                            $computeManagers = (Get-NsxtComputeManager -vCenterServer $vcenter )
                            foreach ($computeManager in $computeManagers) {
                                # TODO: Add support to check the status of a rouge compute manager registration.
                                $customObject = New-Object System.Collections.ArrayList
                                $component = 'Compute Manager' # Define the component name
                                $resource = $vcfNsxDetails.fqdn # Define the resource name
                                $status  = (Get-NsxtComputeManagerStatus -id $computeManager.id)

                                # Set the alert and message based on the status of the registration and connection
                                if ($status.registration_status -eq 'REGISTERED' -and $status.connection_status -eq 'UP') {   
                                    $alert = 'GREEN' # Ok; registered and up
                                    $message = "$($computeManager.server) is registered and healthy." # Set the status message
                                } elseif ($status.registration_status -eq 'REGISTERED' -and $status.connection_status -ne 'UP') {
                                    $alert = 'RED' # Critical; registered and not up
                                    $message = "$($computeManager.server) is registered but unhealthy." # Set the alert message
                                } else {
                                    $alert = 'RED' # Critical; not registered
                                    $message = "($computeManager.server) is not registered." # Critical; failure
                                }

                                # Add the properties to the element object
                                $elementObject = New-Object -TypeName psobject
                                $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component # Set the component name
                                $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $resource # Set the resource name
                                $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert # Set the alert
                                $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue "$message" # Set the message
                                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                    if ($elementObject.alert -eq 'RED') {
                                        $customObject += $elementObject
                                    }
                                }
                                else {
                                    $customObject += $elementObject
                                }  
                            }
                        }
                        $customObject | Sort-Object Component, Resource
                    }
                }
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-NsxtComputeManagerStatus

Function Request-SddcManagerSnapshotStatus {
    <#
		.SYNOPSIS
        Request the snapshot status for the SDDC Manager.

        .DESCRIPTION
        The Request-SddcManagerSnapshotStatus cmdlet checks the snapshot status for SDDC Manager.
        The cmdlet connects to SDDC Manager using the -server, -user, and password values:
        - Validates network connectivity and authenticaton to the SDDC Manager instance
        - Gathers the details for the vCenter Server instance from the SDDC Manager
        - Validates network connectivity and authentication to the vCenter Server instance
        - Performs checks on the snapshot status and outputs the results

        .EXAMPLE
        Request-SddcManagerSnapshotStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
        This example will publish the snapshot status for the SDDC Manager in a VMware Cloud Foundation instance.

        .EXAMPLE
        Request-SddcManagerSnapshotStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -failureOnly
        This example will publish the snapshot status for the SDDC Manager in a VMware Cloud Foundation instance, but for only failed items.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT)) {
                    if (Test-VsphereConnection -server $vcfVcenterDetails.fqdn) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            $customObject = New-Object System.Collections.ArrayList
                            $component = 'SDDC Manager'
                            $resource = 'SDDC Manager Snapshot'
                            $domain = (Get-VCFWorkloadDomain | Sort-Object -Property type, name).name -join ','
                            $snapshotStatus = Get-SnapshotStatus -vm ($server.Split('.')[0])
                            $snapshotCount = ($snapshotStatus | measure).count
                            $snapshotLast = $snapshotStatus.Created | select -Last 1
                            $snapshotAge = [math]::Ceiling(((Get-Date) - ([DateTime]$snapshotLast)).TotalDays)
                            
                            # Set the alert color based on the age of the snapshot
                            if ($snapshotCount -eq 0) {
                                $alert = 'GREEN' # Ok; = 0 snapshots
                                $message = 'No snapshots exist. '
                            }
                            elseif ($snapshotAge -le 1) {
                                $alert = 'GREEN' # OK; <= 1 days
                                $message = 'Latest snapshot is less than 1 day old. '
                            }
                            elseif ($snapshotAge -gt 1 -and $snapshotAge -le 3) {
                                $alert = 'YELLOW' # Warning; > 1 days and <= 3 days
                                $message = 'Latest snapshot is greater than 1 day old. '
                            }
                            elseif ($snapshotAge -gt 3) {
                                $alert = 'RED' # Critical; >= 7 days
                                $message = 'Latest snapshot is greater than 3 days old. '
                            }

                            # Set the alert color based on the number of snapshots.
                            if ($snapshotCount -eq 1) {
                                $messageCount = 'A single snapshot exists. '
                            }
                            elseif ($snapshotCount -gt 1) {
                                $messageCount = 'More than 1 snapshot exist. '
                            }

                            $message += $messageCount # Combine the alert message

                            # Set the alert message based on the snapshot consolidation status.
                            if (Get-SnapshotConsolidation -vm ($server.Split('.')[0])) {
                                $alert = 'RED' # Critical; Consolidation is required
                                $consolidationRequired = $true
                                $messageConsolidation += 'Snapshot consolidation is required.'
                            }
                            else {
                                $consolidationRequired = $false
                            }

                            $message += $messageConsolidation

                            $elementObject = New-Object -TypeName psobject
                            # Add the snapshot details to the PSObject
                            $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component
                            $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $resource
                            $elementObject | Add-Member -NotePropertyName 'Element' -NotePropertyValue $server
                            $elementObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain
                            $elementObject | Add-Member -NotePropertyName 'Snapshots' -NotePropertyValue $snapshotCount
                            $elementObject | Add-Member -NotePropertyName 'Latest' -NotePropertyValue $snapshotLast
                            $elementObject | Add-Member -NotePropertyName 'Consolidation Required' -NotePropertyValue $consolidationRequired
                            $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
                            $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $message
                            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                    $customObject += $elementObject
                                }
                            }
                            else {
                                $customObject += $elementObject
                            }                     
                            $customObject | Sort-Object Component, Resource, Element
                        }
                        Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                    }
                }
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-SddcManagerSnapshotStatus

Function Request-VcenterSnapshotStatus {
    <#
		.SYNOPSIS
        Request the snapshot status for the vCenter Server instance.

        .DESCRIPTION
        The Request-VcenterSnapshotStatus cmdlet checks the snapshot status for vCenter Server instance.
        The cmdlet connects to SDDC Manager using the -server, -user, and password values:
        - Validates network connectivity and authentication to the SDDC Manager instance
        - Gathers the details for the vCenter Server instance from the SDDC Manager
        - Validates network connectivity and authentication to the vCenter Server instance
        - Performs checks on the snapshot status and outputs the results

        .EXAMPLE
        Request-VcenterSnapshotStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will publish the snapshot status for all vCenter Server instances in a VMware Cloud Foundation instance.

        .EXAMPLE
        Request-VcenterSnapshotStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains --failureOnly
        This example will publish the snapshot status for all vCenter Server instances in a VMware Cloud Foundation instance, but only failed items.

        .EXAMPLE
        Request-VcenterSnapshotStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will publish the snapshot status for a vCenter Server instance for a specific workload domain.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if ($PsBoundParameters.ContainsKey('allDomains')) {
                    $allVcenters = Get-VCFvCenter
                    $vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT         
                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            $customObject = New-Object System.Collections.ArrayList    
                            $component = 'vCenter Server'
                            $resource = 'vCenter Server Snapshot'
                            foreach ($vcenter in $allVcenters) {
                                $domain = (Get-VCFWorkloadDomain | Where-Object {$_.vcenters.fqdn -eq $vcenter.fqdn}).name
                                $snapshotStatus = Get-SnapshotStatus -vm ($vcenter.fqdn.Split('.')[0])
                                $snapshotCount = ($snapshotStatus | measure).count
                                $snapshotLast = $snapshotStatus.Created | select -Last 1
                                $snapshotAge = [math]::Ceiling(((Get-Date) - ([DateTime]$snapshotLast)).TotalDays)

                                # Set the alert color based on the age of the snapshot
                                if ($snapshotCount -eq 0) {
                                    $alert = 'GREEN' # Ok; = 0 snapshots
                                    $message = 'No snapshots exist. '
                                }
                                elseif ($snapshotAge -le 1) {
                                    $alert = 'GREEN' # OK; <= 1 days
                                    $message = 'Latest snapshot is less than 1 day old. '
                                }
                                elseif ($snapshotAge -gt 1 -and $snapshotAge -le 3) {
                                    $alert = 'YELLOW' # Warning; > 1 days and <= 3 days
                                    $message = 'Latest snapshot is greater than 1 day old. '
                                }
                                elseif ($snapshotAge -gt 3) {
                                    $alert = 'RED' # Critical; >= 7 days
                                    $message = 'Latest snapshot is greater than 3 days old. '
                                }

                                # Set the alert message based on the number of snapshots.
                                if ($snapshotCount -eq 1) {
                                    $messageCount = 'A single snapshot exists. '
                                }
                                elseif ($snapshotCount -gt 1) {
                                    $messageCount = 'More than 1 snapshot exist. '
                                }

                                $message += $messageCount # Combine the alert message

                                # Set the alert message based on the snapshot consolidation status.
                                if (Get-SnapshotConsolidation -vm ($vcenter.fqdn.Split('.')[0])) {
                                    $alert = 'RED' # Critical; Consolidation is required
                                    $consolidationRequired = $true
                                    $messageConsolidation += 'Snapshot consolidation is required.'
                                }
                                else {
                                    $consolidationRequired = $false
                                }

                                $message += $messageConsolidation

                                $elementObject = New-Object -TypeName psobject
                                # Add the snapshot details to the PSObject
                                $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component
                                $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $resource
                                $elementObject | Add-Member -NotePropertyName 'Element' -NotePropertyValue $vcenter.fqdn
                                $elementObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain
                                $elementObject | Add-Member -NotePropertyName 'Snapshots' -NotePropertyValue $snapshotCount
                                $elementObject | Add-Member -NotePropertyName 'Latest' -NotePropertyValue $snapshotLast
                                $elementObject | Add-Member -NotePropertyName 'Consolidation Required' -NotePropertyValue $consolidationRequired
                                $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
                                $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $message

                                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                    if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                        $customObject += $elementObject
                                    }
                                }
                                else {
                                    $customObject += $elementObject
                                }  
                            }                              
                            $outputObject += $customObject # Add the custom object to the output object    
                        }
                        Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                    }
                }
                else {
                    $vcenter = (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $workloadDomain }).vcenters
                    $vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT
                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            $customObject = New-Object System.Collections.ArrayList    
                            $component = 'vCenter Server'
                            $resource = 'vCenter Server Snapshot'
                            $domain = (Get-VCFWorkloadDomain | Where-Object { $_.vcenters.fqdn -eq $vcenter.fqdn }).name
                            $snapshotStatus = Get-SnapshotStatus -vm ($vcenter.fqdn.Split('.')[0])
                            $snapshotCount = ($snapshotStatus | measure).count
                            $snapshotLast = $snapshotStatus.Created | select -Last 1
                            $snapshotAge = [math]::Ceiling(((Get-Date) - ([DateTime]$snapshotLast)).TotalDays)

                            # Set the alert color based on the age of the snapshot
                            if ($snapshotCount -eq 0) {
                                $alert = 'GREEN' # Ok; = 0 snapshots
                                $message = 'No snapshots exist. '
                            }
                            elseif ($snapshotAge -le 1) {
                                $alert = 'GREEN' # OK; <= 1 days
                                $message = 'Latest snapshot is less than 1 day old. '
                            }
                            elseif ($snapshotAge -gt 1 -and $snapshotAge -le 3) {
                                $alert = 'YELLOW' # Warning; > 1 days and <= 3 days
                                $message = 'Latest snapshot is greater than 1 day old. '
                            }
                            elseif ($snapshotAge -gt 3) {
                                $alert = 'RED' # Critical; >= 7 days
                                $message = 'Latest snapshot is greater than 3 days old. '
                            }

                            # Set the alert message based on the number of snapshots.
                            if ($snapshotCount -eq 1) {
                                $messageCount = 'A single snapshot exists. '
                            }
                            elseif ($snapshotCount -gt 1) {
                                $messageCount = 'More than 1 snapshot exist. '
                            }

                            $message += $messageCount # Combine the alert message

                            # Set the alert message based on the snapshot consolidation status.
                            if (Get-SnapshotConsolidation -vm ($vcenter.fqdn.Split('.')[0])) {
                                $alert = 'RED' # Critical; Consolidation is required
                                $consolidationRequired = $true
                                $messageConsolidation += 'Snapshot consolidation is required.'
                            }
                            else {
                                $consolidationRequired = $false
                            }

                            $message += $messageConsolidation

                            $elementObject = New-Object -TypeName psobject
                            # Add the snapshot details to the PSObject
                            $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component
                            $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $resource
                            $elementObject | Add-Member -NotePropertyName 'Element' -NotePropertyValue $vcenter.fqdn
                            $elementObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain
                            $elementObject | Add-Member -NotePropertyName 'Snapshots' -NotePropertyValue $snapshotCount
                            $elementObject | Add-Member -NotePropertyName 'Latest' -NotePropertyValue $snapshotLast
                            $elementObject | Add-Member -NotePropertyName 'Consolidation Required' -NotePropertyValue $consolidationRequired
                            $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
                            $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $message

                            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                    $customObject += $elementObject
                                }
                            }
                            else {
                                $customObject += $elementObject
                            }                              
                            $outputObject += $customObject # Add the custom object to the output object    
                        }
                        Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                    }
                }
                $outputObject | Sort-Object Component, Resource, Element
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-VcenterSnapshotStatus

Function Request-NsxtEdgeSnapshotStatus {
    <#
		.SYNOPSIS
        Request the snapshot status for NSX Edge nodes.

        .DESCRIPTION
        The Request-NsxtEdgeSnapshotStatus cmdlet checks the snapshot status for NSX Edge nodes.
        The cmdlet connects to SDDC Manager using the -server, -user, and password values:
        - Validates network connectivity and authentication to the SDDC Manager instance
        - Gathers the NSX Manager and NSX Edge node details from the SDDC Manager
        - Validates network connectivity and authentication to the vCenter Server instance
        - Performs checks on the snapshot status and outputs the results

        .EXAMPLE
        Request-NsxtEdgeSnapshotStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will publish the snapshot status for all NSX Edge nodes managed by SDDC Manager in a VMware Cloud Foundation instance.

        .EXAMPLE
        Request-NsxtEdgeSnapshotStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains --failureOnly
        This example will publish the snapshot status for all NSX Edge nodes managed by SDDC Manager in a VMware Cloud Foundation instance, but only failed items.

        .EXAMPLE
        Request-NsxtEdgeSnapshotStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will publish the snapshot status for NSX Edge nodes managed by SDDC Manager for a specific workload domain.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if ($PsBoundParameters.ContainsKey('allDomains')) {
                    $allNsxtManagers = Get-VCFNsxtCluster
                    foreach ($nsxtManager in $allNsxtManagers) {
                        if ($nsxtEdgeDetails = Get-VCFEdgeCluster | Where-Object { $_.nsxtCluster.vipfqdn -eq $nsxtManager.vipFqdn }) {
                            foreach ($nsxtEdgeNode in $nsxtEdgeDetails.edgeNodes) {
                                if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $nsxtManager.domains.name)) {
                                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) { 
                                            $customObject = New-Object System.Collections.ArrayList    
                                            $message = ''
                                            $component = 'NSX'
                                            $resource = 'NSX Edge Node Snapshot'
                                            $domain = $nsxtManager.domains.name
                                            $snapshotStatus = Get-SnapshotStatus -vm ($nsxtEdgeNode.hostName.Split('.')[0])
                                            $snapshotCount = ($snapshotStatus | measure).count
                                            $snapshotLast = $snapshotStatus.Created | select -Last 1
                                            $snapshotAge = [math]::Ceiling(((Get-Date) - ([DateTime]$snapshotLast)).TotalDays)

                                            # Set the alert color based on the age of the snapshot
                                            if ($snapshotCount -eq 0) {
                                                $alert = 'GREEN' # Ok; = 0 snapshots
                                                $message = 'No snapshots exist. '
                                            }
                                            elseif ($snapshotAge -le 1) {
                                                $alert = 'GREEN' # OK; <= 1 days
                                                $message = 'Latest snapshot is less than 1 day old. '
                                            }
                                            elseif ($snapshotAge -gt 1 -and $snapshotAge -le 3) {
                                                $alert = 'YELLOW' # Warning; > 1 days and <= 3 days
                                                $message = 'Latest snapshot is greater than 1 day old. '
                                            }
                                            elseif ($snapshotAge -gt 3) {
                                                $alert = 'RED' # Critical; >= 7 days
                                                $message = 'Latest snapshot is greater than 3 days old. '
                                            }

                                            # Set the alert color based on the number of snapshots.
                                            if ($snapshotCount -eq 1) {
                                                $messageCount = 'A single snapshot exists. '
                                            }
                                            elseif ($snapshotCount -gt 1) {
                                                $messageCount = 'More than 1 snapshot exist. '
                                            }

                                            $message += $messageCount # Combine the alert message

                                            if (Get-SnapshotConsolidation -vm ($nsxtEdgeNode.hostName.Split('.')[0])) {
                                                $alert = 'RED' # Critical; Consolidation is required
                                                $consolidationRequired = $true
                                                $messageConsolidation += 'Snapshot consolidation is required.'
                                            }
                                            else {
                                                $consolidationRequired = $false
                                            }

                                            $message += $messageConsolidation

                                            $elementObject = New-Object -TypeName psobject
                                            # Add the snapshot details to the PSObject
                                            $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component
                                            $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $resource
                                            $elementObject | Add-Member -NotePropertyName 'Element' -NotePropertyValue $nsxtEdgeNode.hostName
                                            $elementObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain
                                            $elementObject | Add-Member -NotePropertyName 'Snapshots' -NotePropertyValue $snapshotCount
                                            $elementObject | Add-Member -NotePropertyName 'Latest' -NotePropertyValue $snapshotLast
                                            $elementObject | Add-Member -NotePropertyName 'Consolidation Required' -NotePropertyValue $consolidationRequired
                                            $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
                                            $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $message

                                            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                                if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                                    $customObject += $elementObject
                                                }
                                            } else {
                                                $customObject += $elementObject
                                            }  
                                        }                              
                                        $outputObject += $customObject # Add the custom object to the output object    
                                    }
                                    Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                                }
                            }
                        }
                    }
                } else {
                $nsxtManager = Get-VCFNsxtCluster | Where-Object { $_.domains.name -eq $workloadDomain }
                if ($nsxtEdgeDetails = Get-VCFEdgeCluster | Where-Object { $_.nsxtCluster.vipfqdn -eq $nsxtManager.vipFqdn }) {
                    foreach ($nsxtEdgeNode in $nsxtEdgeDetails.edgeNodes) {
                        if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $nsxtManager.domains.name)) {
                            if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                                if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                                    $customObject = New-Object System.Collections.ArrayList 
                                    $message = ''
                                    $component = 'NSX'
                                    $resource = 'NSX Edge Node Snapshot'
                                    $domain = $nsxtManager.domains.name
                                    $snapshotStatus = Get-SnapshotStatus -vm ($nsxtEdgeNode.hostName.Split('.')[0])
                                    $snapshotCount = ($snapshotStatus | measure).count
                                    $snapshotLast = $snapshotStatus.Created | select -Last 1
                                    $snapshotAge = [math]::Ceiling(((Get-Date) - ([DateTime]$snapshotLast)).TotalDays)

                                    # Set the alert color based on the age of the snapshot
                                    if ($snapshotCount -eq 0) {
                                        $alert = 'GREEN' # Ok; = 0 snapshots
                                        $messageCount = 'No snapshots exist. ' 
                                    }
                                    elseif ($snapshotAge -le 1) {
                                        $alert = 'GREEN' # OK; <= 1 days
                                        $message = 'Latest snapshot is less than 1 day old. '
                                    }
                                    elseif ($snapshotAge -gt 1 -and $snapshotAge -le 3) {
                                        $alert = 'YELLOW' # Warning; > 1 days and <= 3 days
                                        $message = 'Latest snapshot is greater than 1 day old. '
                                    }
                                    elseif ($snapshotAge -gt 3) {
                                        $alert = 'RED' # Critical; >= 7 days
                                        $message = 'Latest snapshot is greater than 3 days old. '
                                    }

                                    # Set the alert message based on the number of snapshots.
                                    if ($snapshotCount -eq 1) {
                                        $messageCount = 'A single snapshot exists. '
                                    }
                                    elseif ($snapshotCount -gt 1) {
                                        $messageCount = 'More than 1 snapshot exist. '
                                    }

                                    $message += $messageCount # Combine the alert message

                                    # Set the alert message based on snapshots consolidation status.
                                    if (Get-SnapshotConsolidation -vm ($nsxtEdgeNode.hostName.Split('.')[0])) {
                                        $alert = 'RED' # Critical; Consolidation is required
                                        $consolidationRequired = $true
                                        $messageConsolidation += 'Snapshot consolidation is required.'
                                    }
                                    else {
                                        $consolidationRequired = $false
                                    }

                                    $message += $messageConsolidation

                                    $elementObject = New-Object -TypeName psobject
                                    # Add the snapshot details to the PSObject
                                    $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component
                                    $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $resource
                                    $elementObject | Add-Member -NotePropertyName 'Element' -NotePropertyValue $nsxtEdgeNode.hostName
                                    $elementObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain
                                    $elementObject | Add-Member -NotePropertyName 'Snapshots' -NotePropertyValue $snapshotCount
                                    $elementObject | Add-Member -NotePropertyName 'Latest' -NotePropertyValue $snapshotLast
                                    $elementObject | Add-Member -NotePropertyName 'Consolidation Required' -NotePropertyValue $consolidationRequired
                                    $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
                                    $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $message

                                    if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                        if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                            $customObject += $elementObject
                                        }
                                    } else {
                                        $customObject += $elementObject
                                    }  
                                }                              
                                $outputObject += $customObject # Add the custom object to the output object    
                            }
                            Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                        }
                    }                        
                }
            }
        $outputObject | Sort-Object Component, Resource, Element
    }
}
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-NsxtEdgeSnapshotStatus

Function Request-SddcManagerBackupStatus {
    <#
        .SYNOPSIS
        Returns the status of the file-level latest backup task in an SDDC Manager instance.

        .DESCRIPTION
        The Request-SddcManagerBackupStatus cmdlet returns the status of the latest file-level backup task in an SDDC
        Manager instance. The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates network connectivity and authentication to the SDDC Manager instance
        - Collects the latest file-level backup status details

        .EXAMPLE
        Request-SddcManagerBackupStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
        This example will return the status of the latest file-level backup task in an SDDC Manager instance.

        .EXAMPLE
        Request-SddcManagerBackupStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -failureOnly
        This example will return the status of the latest file-level backup task in an SDDC Manager instance but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $backupTasks = Get-VCFTask | Where-Object { $_.type -eq 'SDDCMANAGER_BACKUP' } | Select-Object -First 1
                foreach ($backupTask in $backupTasks) {
                    $customObject = New-Object System.Collections.ArrayList
                    $component = 'SDDC Manager' # Define the component name
                    $date = [DateTime]::ParseExact($backupTask.creationTimestamp, 'yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture) # Define the date
                    $domain = (Get-VCFWorkloadDomain | Sort-Object -Property type, name).name -join ',' # Define the domain(s)
                    $resource = $backupTask.name # Define the resource name
                    $backupAge = [math]::Ceiling(((Get-Date) - ([DateTime]$date)).TotalDays) # Calculate the number of days since the backup was created

                    # Set the status for the backup task
                    if ($backupTask.status -eq 'Successful') {                              
                        $alert = "GREEN" # Ok; success
                    } else {
                        $alert = "RED" # Critical; failure
                    }

                    # Set the message for the backup task
                    if ([string]::IsNullOrEmpty($errors)) {
                        $message = "The backup completed without errors. " # Ok; success
                    } else {
                        $message = "The backup failed with errors. Please investigate before proceeding. " # Critical; failure
                    }

                    # Set the alert and message for the backup task based on the age of the backup
                    if ($backupAge -ge 3) {
                        $alert = "RED" # Critical; >= 3 days
                        $messageBackupAge = "Backup is more than 3 days old." # Set the alert message
                    } elseif ($backupAge -gt 1) {
                        $alert = "YELLOW" # Warning; > 1 days
                        $messageBackupAge = "Backup is more than 1 days old." # Set the alert message
                    } else {
                        $alert = "GREEN" # Ok; <= 1 days
                        $messageBackupAge = "Backup is less than 1 day old." # Set the alert message
                    }

                    $message += $messageBackupAge # Combine the alert message

                    # Set the alert and message if the backup is located on the SDDC Manager.
                    $backupServer = (Get-VCFBackupConfiguration).server # Get the backup server

                    if ($backupServer -eq $server) {
                        $alert = "RED" # Critical; backup server is located on the SDDC Manager.
                        $messageBackupServer = "Backup is located on the SDDC Manager. Reconfigure backups to use another location." # Set the alert message
                        $message = $messageBackupServer # Override the message
                    }
                    # Add Backup Status Properties to the element object
                    $elementObject = New-Object -TypeName psobject
                    $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component # Set the component name
                    $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $resource # Set the name
                    $elementObject | Add-Member -NotePropertyName 'Element' -NotePropertyValue $server # Set the element name
                    $elementObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain # Set the domain(s)
                    $elementObject | Add-Member -NotePropertyName 'Date' -NotePropertyValue $date # Set the timestamp
                    $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert # Set the alert
                    $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue "$message" # Set the message
                    if ($PsBoundParameters.ContainsKey('failureOnly')) {
                        if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                            $customObject += $elementObject
                        }
                    } else {
                        $customObject += $elementObject
                    }  
                }
                $customObject | Sort-Object Component, Resource, Element
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-SddcManagerBackupStatus

Function Request-NsxtManagerBackupStatus {
    <#
        .SYNOPSIS
        Returns the status of the latest file-level backup of an NSX Manager cluster.

        .DESCRIPTION
        The Request-NsxtManagerBackupStatus cmdlet returns the status of the latest backup of an NSX Manager cluster.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates network connectivity and authentication to the SDDC Manager instance
        - Gathers the details for the NSX Manager cluster from the SDDC Manager
        - Validates network connectivity and authentication to the NSX Manager cluster
        - Collects the file-level backup status details

        .EXAMPLE
        Request-NsxtManagerBackupStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return the status of the latest file-level backup of an NSX Manager cluster managed by SDDC Manager for a workload domain.

        .EXAMPLE
        Request-NsxtManagerBackupStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
        This example will return the status of the latest file-level backup of an NSX Manager cluster managed by SDDC Manager for a workload domain but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfNsxDetails = Get-NsxtServerDetail -fqdn $server -username $user -password $pass -domain $domain)) {
                    if (Test-NSXTConnection -server $vcfNsxDetails.fqdn) {
                        if (Test-NSXTAuthentication -server $vcfNsxDetails.fqdn -user ($vcfNsxDetails.adminUser | Select-Object -first 1) -pass ($vcfNsxDetails.adminPass | Select-Object -first 1)) {
                            $backupTask = Get-NsxtBackupHistory -fqdn $vcfNsxDetails.fqdn
                            $customObject = New-Object System.Collections.ArrayList

                            # NSX Node Backup
                            $component = 'NSX Manager' # Define the component name
                            $resource = 'Node Backup Operation' # Define the resource name

                            foreach ($element in $backupTask.node_backup_statuses) {
                                $timestamp = [DateTimeOffset]::FromUnixTimeMilliseconds($backupTask.node_backup_statuses.end_time).DateTime
                                $backupAge = [math]::Ceiling(((Get-Date) - ([DateTime]$timestamp)).TotalDays) # Calculate the number of days since the backup was created

                                # Set the alert and message based on the status of the backup
                                if ($backupTask.node_backup_statuses.success -eq $true) {   
                                    $alert = "GREEN" # Ok; success
                                    $message = 'The backup completed without errors. ' # Set the backup status message
                                } else {
                                    $alert = "RED" # Critical; failure
                                    $message = "The backup failed with errors. Please investigate before proceeding. " # Critical; failure
                                }

                                # Set the alert and message update for the backup task based on the age of the backup
                                if ($backupAge -ge 3) {
                                    $alert = 'RED' # Critical; >= 3 days
                                    $messageBackupAge = 'Backup is more than 3 days old.' # Set the alert message
                                } elseif ($backupAge -gt 1) {
                                    $alert = 'YELLOW' # Warning; > 1 days
                                    $messageBackupAge = 'Backup is more than 1 days old.' # Set the alert message
                                } else {
                                    $alert = 'GREEN' # Ok; <= 1 days
                                    $messageBackupAge = 'Backup is less than 1 day old.' # Set the alert message
                                }

                                $message += $messageBackupAge # Combine the alert message

                                # Set the alert and message if the backup is located on the SDDC Manager.
                                $backupServer = (Get-NsxtBackupConfiguration -fqdn $vcfNsxDetails.fqdn).remote_file_server.server # Get the backup server

                                if ($backupServer -eq $server) {
                                    $alert = 'RED' # Critical; backup server is located on the SDDC Manager.
                                    $messageBackupServer = "Backup is located on the SDDC Manager ($server). Reconfigure backups to use another location." # Set the alert message
                                    $message = $messageBackupServer # Override the message
                                }

                                # Add Backup Status Properties to the element object
                                $elementObject = New-Object -TypeName psobject
                                $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component # Set the component name
                                $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $resource # Set the resource name
                                $elementObject | Add-Member -NotePropertyName 'Element' -NotePropertyValue $vcfNsxDetails.fqdn # Set the element name
                                $elementObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain # Set the domain
                                $elementObject | Add-Member -NotePropertyName 'Date' -NotePropertyValue $timestamp # Set the end timestamp
                                $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert # Set the alert
                                $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue "$message" # Set the message
                                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                    if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                        $customObject += $elementObject
                                    }
                                } else {
                                    $customObject += $elementObject
                                }  
                            }

                            $outputObject += $customObject # Add the custom object to the output object
                            
                            # NSX Cluster Backup
                            $component = 'NSX Manager' # Define the component name
                            $resource = 'Cluster Backup Operation' # Define the resource name
                            foreach ($element in $backupTask.cluster_backup_statuses) {
                                $timestamp = [DateTimeOffset]::FromUnixTimeMilliseconds($backupTask.cluster_backup_statuses.end_time).DateTime
                                $backupAge = [math]::Ceiling(((Get-Date) - ([DateTime]$timestamp)).TotalDays) # Calculate the number of days since the backup was created

                                # Set the alert and message based on the status of the backup
                                if ($backupTask.node_backup_statuses.success -eq $true) {   
                                    $alert = 'GREEN' # Ok; success
                                    $message = 'The backup completed without errors. ' # Set the backup status message
                                } else {
                                    $alert = 'RED' # Critical; failure
                                    $message = 'The backup failed with errors. Please investigate before proceeding. ' # Critical; failure
                                }

                                # Set the alert and message update for the backup task based on the age of the backup
                                if ($backupAge -ge 3) {
                                    $alert = 'RED' # Critical; >= 3 days
                                    $messageBackupAge = 'Backup is more than 3 days old.' # Set the alert message
                                } elseif ($backupAge -gt 1) {
                                    $alert = 'YELLOW' # Warning; > 1 days
                                    $messageBackupAge = 'Backup is more than 1 days old.' # Set the alert message
                                } else {
                                    $alert = 'GREEN' # Ok; <= 1 days
                                    $messageBackupAge = 'Backup is less than 1 day old.' # Set the alert message
                                }

                                $message += $messageBackupAge # Combine the alert message

                                # Set the alert and message if the backup is located on the SDDC Manager.
                                $backupServer = (Get-NsxtBackupConfiguration -fqdn $vcfNsxDetails.fqdn).remote_file_server.server # Get the backup server

                                if ($backupServer -eq $server) {
                                    $alert = 'RED' # Critical; backup server is located on the SDDC Manager.
                                    $messageBackupServer = "Backup is located on the SDDC Manager ($server). Reconfigure backups to use another location." # Set the alert message
                                    $message = $messageBackupServer # Override the message
                                }

                                # Add Backup Status Properties to the element object
                                $elementObject = New-Object -TypeName psobject
                                $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component # Set the component name
                                $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $resource # Set the resource name
                                $elementObject | Add-Member -NotePropertyName 'Element' -NotePropertyValue $vcfNsxDetails.fqdn # Set the element name
                                $elementObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain # Set the domain
                                $elementObject | Add-Member -NotePropertyName 'Date' -NotePropertyValue $timestamp # Set the end timestamp
                                $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert # Set the alert
                                $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue "$message" # Set the message
                                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                    if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                        $customObject += $elementObject
                                    }
                                } else {
                                    $customObject += $elementObject
                                }  
                            }

                            $outputObject += $customObject # Add the custom object to the output object

                            # NSX Cluster Backup
                            $component = 'NSX Manager' # Define the component name
                            $resource = 'Inventory Backup Operation' # Define the resource name
                            foreach ($element in $backupTask.cluster_backup_statuses) {
                                $timestamp = [DateTimeOffset]::FromUnixTimeMilliseconds($backupTask.cluster_backup_statuses.end_time).DateTime
                                $backupAge = [math]::Ceiling(((Get-Date) - ([DateTime]$timestamp)).TotalDays) # Calculate the number of days since the backup was created

                                # Set the alert and message based on the status of the backup
                                if ($backupTask.node_backup_statuses.success -eq $true) {   
                                    $alert = 'GREEN' # Ok; success
                                    $message = 'The backup completed without errors. ' # Set the backup status message
                                } else {
                                    $alert = 'RED' # Critical; failure
                                    $message = 'The backup failed with errors. Please investigate before proceeding. ' # Critical; failure
                                }

                                # Set the alert and message update for the backup task based on the age of the backup
                                if ($backupAge -ge 3) {
                                    $alert = 'RED' # Critical; >= 3 days
                                    $messageBackupAge = 'Backup is more than 3 days old.' # Set the alert message
                                } elseif ($backupAge -gt 1) {
                                    $alert = 'YELLOW' # Warning; > 1 days
                                    $messageBackupAge = 'Backup is more than 1 days old.' # Set the alert message
                                } else {
                                    $alert = 'GREEN' # Ok; <= 1 days
                                    $messageBackupAge = 'Backup is less than 1 day old.' # Set the alert message
                                }

                                $message += $messageBackupAge # Combine the alert message

                                # Set the alert and message if the backup is located on the SDDC Manager.
                                $backupServer = (Get-NsxtBackupConfiguration -fqdn $vcfNsxDetails.fqdn).remote_file_server.server # Get the backup server

                                if ($backupServer -eq $server) {
                                    $alert = 'RED' # Critical; backup server is located on the SDDC Manager.
                                    $messageBackupServer = "Backup is located on the SDDC Manager ($server). Reconfigure backups to use another location." # Set the alert message
                                    $message = $messageBackupServer # Override the message
                                }

                                # Add Backup Status Properties to the element object
                                $elementObject = New-Object -TypeName psobject
                                $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component # Set the component name
                                $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $resource # Set the resource name
                                $elementObject | Add-Member -NotePropertyName 'Element' -NotePropertyValue $vcfNsxDetails.fqdn # Set the element name
                                $elementObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain # Set the domain
                                $elementObject | Add-Member -NotePropertyName 'Date' -NotePropertyValue $timestamp # Set the end timestamp
                                $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert # Set the alert
                                $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue "$message" # Set the message
                                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                    if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                        $customObject += $elementObject
                                    }
                                } else {
                                    $customObject += $elementObject
                                }  
                            }
                            $customObject | Sort-Object Domain, Element, Resource                
                        }
                    }
                }
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-NsxtManagerBackupStatus

Function Request-VcenterBackupStatus {
    <#
        .SYNOPSIS
        Returns the status of the file-level latest backup of a vCenter Server instance.

        .DESCRIPTION
        The Request-VcenterBackupStatus cmdlet returns the status of the latest backup of a vCenter Server instance.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates network connectivity and authentication to the SDDC Manager instance
        - Gathers the details for the NvCenter Server instance from the SDDC Manager
        - Validates network connectivity and authentication to the vCenter Server instance
        - Collects the file-level backup status details

        .EXAMPLE
        Request-VcenterBackupStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return the status of the latest file-level backup of a vCenter Server instance managed by SDDC Manager for a workload domain.

        .EXAMPLE
        Request-VcenterBackupStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
        This example will return the status of the latest file-level backup of a vCenter Server instance managed by SDDC Manager for a workload domain but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly

    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfVcenterDetails = Get-VcenterServerDetail -server $server -user $user -pass $pass -domain $domain)) {
                    if (Test-VsphereConnection -server $vcfVcenterDetails.fqdn) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            Connect-CisServer -server $vcfVcenterDetails.fqdn -username $vcfVcenterDetails.ssoAdmin -password $vcfVcenterDetails.ssoAdminPass | Out-Null
                            $backupTask = Get-VcenterBackupJobs | Select-Object -First 1 | Get-VcenterBackupStatus
                            $customObject = New-Object System.Collections.ArrayList
                            $component = 'vCenter Server' # Define the component name
                            $resource = 'vCenter Server Backup Operation' # Define the resource name
                            $timestamp = $backupTask.end_time # Define the end timestamp
                            if ($timestamp) {
                                $backupAge = [math]::Ceiling(((Get-Date) - ([DateTime]$timestamp)).TotalDays) # Calculate the number of days since the backup was created
                            }

                            # Set the status for the backup task
                            if ($backupTask.state -eq 'SUCCEEDED') {                              
                                $alert = "Green" # Ok; success
                            } elseif ($backupTask.state -eq 'IN PROGRESS') {                              
                                $alert = "YELLOW" # Warning; in progress
                            } else {
                                $alert = "RED" # Critical; failure
                            }

                            if ($timestamp) {
                                # Set the message for the backup task
                                if ([String]::IsNullOrEmpty($messages)) {
                                    $Message = "The backup completed without errors. " # Ok; success
                                } else {
                                    $message = "The backup failed with errors. Please investigate before proceeding. " # Critical; failure
                                }
                            }

                            # Set the alert and message update for the backup task based on the age of the backup
                            if ($null -eq $backupAge) {
                                $alert = "RED" # Critical; 
                                $messageBackupAge = "Backup has never been run or not configured. " # Set the alert message
                            } elseif ($backupAge -ge 3) {
                                $alert = "RED" # Critical; >= 3 days
                                $messageBackupAge = "Backup is more than 3 days old." # Set the alert message
                            } elseif ($backupAge -gt 1) {
                                $alert = "YELLOW" # Warning; > 1 days
                                $messageBackupAge = "Backup is more than 1 days old." # Set the alert message
                            } else {
                                $alert = "GREEN" # Ok; <= 1 days
                                $messageBackupAge = "Backup is less than 1 day old." # Set the alert message
                            }

                            $message += $messageBackupAge # Combine the alert message

                            # Set the alert and message if the backup is located on the SDDC Manager.
                            $backupServer = (Get-VcenterBackupConfiguration).location # Get the backup server

                            if ($backupServer.host -eq $server) { # Compare against the `host` attribute
                                $alert = 'RED' # Critical; backup server is located on the SDDC Manager.
                                $messageBackupServer = "Backup is located on the SDDC Manager ($server). Reconfigure backups to use another location." # Set the alert message
                                $message = $messageBackupServer # Override the message
                            }

                            # Add Backup Status Properties to the element object
                            $elementObject = New-Object -TypeName psobject
                            $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component # Set the component name
                            $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $resource # Set the resource name
                            $elementObject | Add-Member -NotePropertyName 'Element' -NotePropertyValue $vcfVcenterDetails.fqdn # Set the element name
                            $elementObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain # Set the domain(s)
                            $elementObject | Add-Member -NotePropertyName 'Date' -NotePropertyValue $timestamp # Set the timestamp
                            $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert # Set the alert
                            $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue "$message" # Set the message
                            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                    $customObject += $elementObject
                                }
                            } else {
                                $customObject += $elementObject
                            }  

                            $customObject | Sort-Object Component, Resource, Element

                            Disconnect-CisServer -Server $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                        }
                    }
                }
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-VcenterBackupStatus

Function Request-DatastoreStorageCapacity {
    <#
		.SYNOPSIS
        Checks the datastore usage in all vCenter Server instances.

        .DESCRIPTION
        The Request-DatastoreStorageCapacity cmdlet checks the datastore usage in all vCenters. The cmdlet 
        connects to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Gathers the details for each vCenter Server
        - Collects information about datastore usage
        
        .EXAMPLE
        Request-DatastoreStorageCapacity -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
        This example will check datastores on all vCenter Servers managed by SDDC Manager in a VMware Cloud Foundation instance but only failed items.

        .EXAMPLE
        Request-DatastoreStorageCapacity -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will check datastore on a vCenter Servers managed by SDDC Manager for a workload domain.

    #>
    
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )
        
    # Define thresholds Green < Yellow < Red
    $greenThreshold = 80
    $redThreshold = 90

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $customObject = New-Object System.Collections.ArrayList
                $vcenter = (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $domain }).vcenters
                $vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT
                if (Test-VsphereConnection -server $($vcenter.fqdn)) {
                    if (Test-VsphereAuthentication -server $vcenter.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                        Connect-VIServer -Server $vcenter.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass | Out-Null
                        $datastores = Get-Datastore
                        foreach ($datastore in $datastores) {
                            # Calculate datastore usage and capacity
                            $usage = [math]::Round((($datastore.CapacityGB - $datastore.FreeSpaceGB) / $datastore.CapacityGB * 100))
                            $usage = [int]$usage
                            $capacity = [int]$datastore.CapacityGB

                            # Applying thresholds and creating collection from input
                            Switch ($usage) {
                                { $_ -le $greenThreshold } {
                                    $alert = 'GREEN' # Green if $usage is up to $greenThreshold
                                    $message = "Used space is less than $greenThreshold%."
                                }
                                { $_ -ge $redThreshold } {
                                    $alert = 'RED' # Red if $usage is equal or above $redThreshold
                                    $message = "Used space is above $redThreshold%. Please reclaim space on the datastore."
                                }
                                Default {
                                    $alert = 'YELLOW' # Yellow if above two are not matched
                                    $message = "Used space is between $greenThreshold% and $redThreshold%. Please consider reclaiming some space on the datastore."
                                }
                            }

                            # Populate data into the object
                            if (($PsBoundParameters.ContainsKey("failureOnly")) -and ($alert -eq 'GREEN')) { continue } # Skip population of object if "failureOnly" is selected and alert is "GREEN"
                            $userObject = New-Object -TypeName psobject
                            $userObject | Add-Member -notepropertyname 'vCenter Server' -notepropertyvalue $vcenter.fqdn
                            $userObject | Add-Member -notepropertyname 'Datastore Name' -notepropertyvalue $datastore.Name
                            $userObject | Add-Member -notepropertyname 'Datastore Type' -notepropertyvalue $datastore.Type.ToUpper()
                            $userObject | Add-Member -notepropertyname 'Size (GB)' -notepropertyvalue $capacity
                            $userObject | Add-Member -notepropertyname 'Used %' -notepropertyvalue $usage
                            $userObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $alert
                            $userObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $message
                            $customObject += $userObject # Creating collection to work with afterwords
                        }
                        Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                    }
                    $customObject | Sort-Object 'vCenter Server', 'Datastore Type', 'Datastore Name'
                }
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    } 
    
}
Export-ModuleMember -Function Request-DatastoreStorageCapacity

Function Request-VcenterStorageHealth {
    <#
		.SYNOPSIS
        Checks the disk usage on a vCenter Server instance.

        .DESCRIPTION
        The Request-VcenterStorageHealth cmdlets checks the disk space usage on a vCenter Server. The cmdlet 
        connects to SDDC Manager using the -server, -user, and -password values:
        - Validates network connectivity and authentication to the SDDC Manager instance
        - Validates network connectivity and authentication to the vCenter Server instance
        - Collects information for the disk usage
        - Checks disk usage against thresholds and outputs the results

        .EXAMPLE
        Request-VcenterStorageHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will check disk usage for a single workload domain

        .EXAMPLE
        Request-VcenterStorageHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -failureOnly
        This example will check the disk usage for all vCenter Server instances but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT)) {
                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            $command = 'df -h | grep -e "^/" | grep -v "/dev/loop"' # Define Command for Retriveing Disk Information
                            $vcenter = (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $domain }).vcenters
                            $rootPass = (Get-VCFCredential | Where-Object { $_.credentialType -eq "SSH" -and $_.resource.resourceName -eq $vcenter.fqdn }).password
                            $dfOutput = Invoke-VMScript -VM ($vcenter.fqdn.Split(".")[0]) -ScriptText $command -GuestUser root -GuestPassword $rootPass -Server $vcfVcenterDetails.fqdn

                            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                                Format-DfStorageHealth -dfOutput $dfOutput -systemFqdn $vcenter.fqdn -failureOnly
                            }
                            else {
                                Format-DfStorageHealth -dfOutput $dfOutput -systemFqdn $vcenter.fqdn
                            }
                        }
                        Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                    }
                }
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-VcenterStorageHealth

Function Request-SddcManagerStorageHealth {
    <#
		.SYNOPSIS
        Checks the storage health (capacity) in an SDDC Manager appliance.

        .DESCRIPTION
        The Request-SddcManagerStorageHealth cmdlet checks the disk free space on the SDDC Manager appliance. 
        The cmdlet connects to SDDC Manager using the -server, -user, and password values:
        - Performs checks on the local storage used space and outputs the results

        .EXAMPLE
        Request-SddcManagerStorageHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -rootPass VMw@re1!
        This example checks the hard disk space in the SDDC Manager appliance.

        .EXAMPLE
        Request-SddcManagerStorageHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -rootPass VMw@re1! -failureOnly
        This example checks the hard disk space in the SDDC Manager appliance and outputs only the failures.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$rootPass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )
    
    Try {
        $command = 'df -h | grep -e "^/" | grep -v "/dev/loop"' # Define Command for Retriveing Disk Information
        $dfOutput = Invoke-SddcCommand -server $server -user $user -pass $pass -rootPass $rootPass -command $command # Get Disk Information from SDDC Manager

        if ($PsBoundParameters.ContainsKey("failureOnly")) {
            Format-DfStorageHealth -dfOutput $dfOutput -systemFqdn $server -failureOnly
        } else {
            Format-DfStorageHealth -dfOutput $dfOutput -systemFqdn $server
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    } 
}
Export-ModuleMember -Function Request-SddcManagerStorageHealth

Function Request-EsxiStorageCapacity {
    <#
		.SYNOPSIS
        Checks the disk usage for ESXi hosts.

        .DESCRIPTION
        The Request-EsxiStorageCapacity cmdlets checks the disk space usage on ESXi hosts. The cmdlet connects to SDDC
        Manager using the -server, -user, and -password values:
        - Validates network connectivity and authentication to the SDDC Manager instance
        - Collects disk usage information for each ESXi host in the Workload Domain
        - Checks disk usage against thresholds and outputs the results

        .EXAMPLE
        Request-EsxiStorageCapacity -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will check disk usage for ESXi hosts managed by SDDC Manager for a single workload domain.

        .EXAMPLE
        Request-EsxiStorageCapacity -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
        This example will check disk usage for ESXi hosts managed by SDDC Manager for a single workload domain but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $esxiPartitionsObject = New-Object System.Collections.ArrayList
                if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain)) {
                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            $esxiHosts = Get-VMHost -Server $vcfVcenterDetails.fqdn
                            Foreach ($esxiHost in $esxiHosts) {
                                $esxcli = Get-EsxCli -VMhost $esxiHost.Name -V2
                                $allPrtitions = $esxcli.storage.filesystem.list.invoke()
                                foreach ($partition in $allPrtitions) {
                                    if ($partition.Type -eq "VMFS-L" -or $partition.Type -eq "vfat") {
                                        $threshold = Format-StorageThreshold -size $partition.Size -free $partition.Free
                                        $esxiPartition = New-Object -TypeName psobject
                                        $esxiPartition | Add-Member -notepropertyname 'Domain' -notepropertyvalue $domain
                                        $esxiPartition | Add-Member -notepropertyname 'ESXi FQDN' -notepropertyvalue $esxiHost.Name
                                        $esxiPartition | Add-Member -notepropertyname 'Volume Name' -notepropertyvalue $partition.VolumeName.ToLower()
                                        $esxiPartition | Add-Member -notepropertyname 'Filesystem' -notepropertyvalue $partition.Type.ToLower()
                                        $esxiPartition | Add-Member -notepropertyname 'Used %' -notepropertyvalue $threshold.usage
                                        $esxiPartition | Add-Member -notepropertyname 'Alert' -notepropertyvalue $threshold.alert
                                        $esxiPartition | Add-Member -notepropertyname 'Message' -notepropertyvalue $threshold.message
                                        if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                            if (($esxiPartition.alert -eq 'RED') -or ($esxiPartition.alert -eq 'YELLOW')) {
                                                $esxiPartitionsObject += $esxiPartition
                                            }
                                        } else {
                                            $esxiPartitionsObject += $esxiPartition
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                }
                $esxiPartitionsObject | Sort-Object Domain, 'ESXi FQDN', 'Volume Name', Alert
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-EsxiStorageCapacity

Function Publish-ComponentConnectivityHealth {
    <#
		.SYNOPSIS
        Request and publish Component Connectivity Health.

        .DESCRIPTION
        The Publish-ComponentConnectivityHealth cmdlet checks component connectivity across the VMware Cloud Foundation
        instance and prepares the data to be published to an HTML report. The cmdlet connects to SDDC Manager using the
        -server, -user, and password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Performs connectivityy health checks and outputs the results

        .EXAMPLE
        Publish-ComponentConnectivityHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -json <json-file> -allDomains
        This example checks the component connectivity for all Workload Domains across the VMware Cloud Foundation instance.

        .EXAMPLE
        Publish-ComponentConnectivityHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -json <json-file> -workloadDomain sfo-w01
        This example checks the component connectivity for a single Workload Domain in a VMware Cloud Foundation instance.

        .EXAMPLE
        Publish-ComponentConnectivityHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -json <json-file> -allDomains -failureOnly
        This example checks the component connectivity for all Workload Domains across the VMware Cloud Foundation instance but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$json,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        $allConnectivityObject = New-Object System.Collections.ArrayList
        if ($PsBoundParameters.ContainsKey('failureOnly')) {
            if ($PsBoundParameters.ContainsKey("allDomains")) {
                $vcenterConnectivity = Request-VcenterAuthentication -server $server -user $user -pass $pass -alldomains -failureOnly; $allConnectivityObject += $vcenterConnectivity
                $NsxtConnectivity = Request-NsxtAuthentication -server $server -user $user -pass $pass -alldomains -failureOnly; $allConnectivityObject += $NsxtConnectivity
            }
            else {
                $vcenterConnectivity = Request-VcenterAuthentication -server $server -user $user -pass $pass -workloadDomain $workloadDomain -failureOnly; $allConnectivityObject += $vcenterConnectivity
                $NsxtConnectivity = Request-NsxtAuthentication -server $server -user $user -pass $pass -workloadDomain $workloadDomain -failureOnly; $allConnectivityObject += $NsxtConnectivity
            }
            $connectivityRaw = Publish-ConnectivityHealth -json $json -failureOnly
        }
        else {
            if ($PsBoundParameters.ContainsKey("allDomains")) {
                $vcenterConnectivity = Request-VcenterAuthentication -server $server -user $user -pass $pass -alldomains; $allConnectivityObject += $vcenterConnectivity
                $NsxtConnectivity = Request-NsxtAuthentication -server $server -user $user -pass $pass -alldomains; $allConnectivityObject += $NsxtConnectivity
            }
            else {
                $vcenterConnectivity = Request-VcenterAuthentication -server $server -user $user -pass $pass -workloadDomain $workloadDomain; $allConnectivityObject += $vcenterConnectivity
                $NsxtConnectivity = Request-NsxtAuthentication -server $server -user $user -pass $pass -workloadDomain $workloadDomain; $allConnectivityObject += $NsxtConnectivity
            }
            $connectivityRaw = Publish-ConnectivityHealth -json $json
        }
        $allConnectivityObject += $connectivityRaw
        if ($allConnectivityObject.Count -eq 0) { $addNoIssues = $true }
        if ($addNoIssues) {
            $allConnectivityObject = $allConnectivityObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="general-connectivity"></a><h3>Connectivity Health Status</h3>' -PostContent '<p>No issues found.</p>' 
        } else {
            $allConnectivityObject = $allConnectivityObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="general-connectivity"></a><h3>Connectivity Health Status</h3>' -As Table
        }
        $allConnectivityObject = Convert-CssClass -htmldata $allConnectivityObject
        $allConnectivityObject
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-ComponentConnectivityHealth

Function Request-VcenterAuthentication {
    <#
		.SYNOPSIS
        Checks API authentication to vCenter Server instance.

        .DESCRIPTION
        The Request-VcenterAuthentication cmdlets checks the authentication to vCenter Server instance. The cmdlet 
        connects to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance

        .EXAMPLE
        Request-VcenterAuthentication -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will check authentication to vCenter Server API for all vCenter Server instances managed by SDDC Manager.

        .EXAMPLE
        Request-VcenterAuthentication -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will check authentication to vCenter Server API for a single workload domain

        .EXAMPLE
        Request-VcenterAuthentication -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -failureOnly
        This example will check authentication to vCenter Server API for all vCenter Server instances but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $account = (Get-VCFCredential | Where-Object {$_.accountType -eq "SYSTEM" -and $_.resource.resourceType -eq "PSC"})
                $customObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey("allDomains")) { 
                    $allWorkloadDomains = Get-VCFWorkloadDomain
                    foreach ($domain in $allWorkloadDomains) {
                        if (Test-vSphereApiAuthentication -server $domain.vcenters.fqdn -user $account.username -pass $account.password) {
                            $alert = "GREEN"
                            $message = "API Connection check successful!"
                        }
                        else {
                            $alert = "RED"
                            $message = "API Connection check failed!"
                        }
                        $elementObject = New-Object System.Collections.ArrayList
                        $elementObject = New-Object -TypeName psobject
                        $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue "vCenter"
                        $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $domain.vcenters.fqdn
                        $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
                        $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $message
                        if ($PsBoundParameters.ContainsKey('failureOnly')) {
                            if (($elementObject.alert -eq 'RED')) {
                                $customObject += $elementObject
                            }
                        }
                        else {
                            $customObject += $elementObject
                        }
                    }
                }
                else {
                    $vcenter = (Get-VCFWorkloadDomain | Where-Object {$_.name -eq $workloadDomain}).vcenters.fqdn
                    if (Test-vSphereApiAuthentication -server $vcenter -user $account.username -pass $account.password) {
                        $alert = "GREEN"
                        $message = "API Connection check successful!"
                    }
                    else {
                        $alert = "RED"
                        $message = "API Connection check failed!"
                    }
                    $elementObject = New-Object System.Collections.ArrayList
                    $elementObject = New-Object -TypeName psobject
                    $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue "vCenter"
                    $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $vcenter
                    $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
                    $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $message
                    if ($PsBoundParameters.ContainsKey('failureOnly')) {
                        if (($elementObject.alert -eq 'RED')) {
                            $customObject += $elementObject
                        }
                    }
                    else {
                        $customObject += $elementObject
                    }
                }

                $customObject | Sort-Object Component, Resource
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-VcenterAuthentication

Function Request-NsxtAuthentication {
    <#
		.SYNOPSIS
        Checks API authentication to NSX Manager instance.

        .DESCRIPTION
        The Request-NsxtAuthentication cmdlets checks the authentication to NSX Manager instance. The cmdlet 
        connects to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the NSX Manager instance

        .EXAMPLE
        Request-NsxtAuthentication -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will check authentication to NSX Manager API for all NSX Manager instances managed by SDDC Manager.

        .EXAMPLE
        Request-NsxtAuthentication -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will check authentication to NSX Manager API for a single workload domain

        .EXAMPLE
        Request-NsxtAuthentication -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -failureOnly
        This example will check authentication to NSX Manager API for all NSX Manager instances but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $customObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey("allDomains")) { 
                    $allWorkloadDomains = Get-VCFWorkloadDomain
                    foreach ($domain in $allWorkloadDomains) {
                        $vcfNsxDetails = Get-NsxtServerDetail -fqdn $server -username $user -password $pass -domain $domain.name -listNodes
                        foreach ($node in $vcfNsxDetails.nodes) {
                            if (Test-NsxtConnection -server $node.fqdn -ErrorAction SilentlyContinue -ErrorVariable ErrorMessage ) {
                                if (Test-NsxtAuthentication -server $node.fqdn -user ($vcfNsxDetails.adminUser | Select-Object -first 1) -pass ($vcfNsxDetails.adminPass | Select-Object -first 1)) {
                                    $alert = "GREEN"
                                    $message = "API Connection check successful!"
                                }
                                else {
                                    $alert = "RED"
                                    $message = "API Connection check failed!"
                                }
                            } else {
                                $alert = "RED"
                                $message = "API Connection check failed! " + $ErrorMessage
                            }
                            $elementObject = New-Object System.Collections.ArrayList
                            $elementObject = New-Object -TypeName psobject
                            $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue "NSX"
                            $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $node.fqdn
                            $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
                            $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $message
                            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                if (($elementObject.alert -eq 'RED')) {
                                    $customObject += $elementObject
                                }
                            }
                            else {
                                $customObject += $elementObject
                            }
                        }
                    }
                }
                else {
                    $vcfNsxDetails = Get-NsxtServerDetail -fqdn $server -username $user -password $pass -domain $workloadDomain -listNodes
                    foreach ($node in $vcfNsxDetails.nodes) {
                        if (Test-NsxtConnection -server $node.fqdn -ErrorAction SilentlyContinue -ErrorVariable ErrorMessage ) {
                            if (Test-NsxtAuthentication -server $node.fqdn -user ($vcfNsxDetails.adminUser | Select-Object -first 1) -pass ($vcfNsxDetails.adminPass | Select-Object -first 1)) {
                                $alert = "GREEN"
                                $message = "API Connection check successful!"
                            }
                            else {
                                $alert = "RED"
                                $message = "API Connection check failed!"
                            }
                        } else {
                            $alert = "RED"
                            $message = $ErrorMessage
                        }
                        $elementObject = New-Object System.Collections.ArrayList
                        $elementObject = New-Object -TypeName psobject
                        $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue "NSX"
                        $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $node.fqdn
                        $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
                        $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $message
                        if ($PsBoundParameters.ContainsKey('failureOnly')) {
                            if (($elementObject.alert -eq 'RED')) {
                                $customObject += $elementObject
                            }
                        }
                        else {
                            $customObject += $elementObject
                        }
                    }  
                }
                
                $customObject | Sort-Object Component, Resource
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-NsxtAuthentication

Function Request-NsxtTransportNodeStatus {
    <#
        .SYNOPSIS
        Returns the status of NSX transport nodes managed by an NSX Manager cluster.

        .DESCRIPTION
        The Request-NsxtTransportNodeStatus cmdlet returns the status NSX transport nodes managed by an NSX Manager cluster.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates network connectivity and authentication to the SDDC Manager instanc
        - Gathers the details for the NSX Manager cluster from the SDDC Manager
        - Validates network connectivity and authentication to the NSX Local Manager cluster
        - Collects the status of the transport nodes

        .EXAMPLE
        Request-NsxtTransportNodeStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return the status of the NSX transport nodes managed by an NSX Manager cluster which is managed by SDDC Manager for a workload domain.

        .EXAMPLE
        Request-NsxtTransportNodeStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
        This example will return the status of the NSX transport nodes managed by an NSX Manager cluster which is managed by SDDC Manager for a workload domain but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfNsxDetails = Get-NsxtServerDetail -fqdn $server -username $user -password $pass -domain $domain)) {
                    if (Test-NSXTConnection -server $vcfNsxDetails.fqdn) {
                        if (Test-NSXTAuthentication -server $vcfNsxDetails.fqdn -user ($vcfNsxDetails.adminUser | Select-Object -First 1) -pass ($vcfNsxDetails.adminPass | Select-Object -First 1)) {
                            $customObject = New-Object System.Collections.ArrayList
                            
                            # NSX Transport Nodes
                            $types = @("edge","host")
                            foreach ($type in $types) {
                                $component = 'NSX Transport Node' # Define the component name
                                $resource = $vcfNsxDetails.fqdn # Define the resource name
                                $transportNodeStatus = (Get-NsxtTransportNodeStatus -type $type) # Get the status of the transport nodes
                                $nodeType = (Get-Culture).textinfo.ToTitleCase($type.ToLower()) # Convert the type to title case

                                # Set the alert and message based on the status of the transport node
                                if ($downCount -ge 0 -or $unknownCount -ge 0) {
                                    $alert = 'Red' # Critical, transport node(s) down or unknown
                                    $message = $nodeType + ' transport node(s) in down or unknown state.' # Set the alert message
                                }
                                elseif ($degradedCount -ge 0) {
                                    $alert = 'Yellow' # Warning, transport node(s) degraded
                                    $message = $nodeType + ' transport node(s) in degraded state.' #
                                }
                                else {
                                    $alert = 'Green' # OK, transport node(s)  up
                                    $message = $nodeType + ' transport node(s) in up state.' # Set the alert message
                                }

                                # Add the properties to the element object
                                $elementObject = New-Object -TypeName psobject
                                $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component # Set the component name
                                $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $resource # Set the resource name
                                $elementObject | Add-Member -NotePropertyName 'Element' -NotePropertyValue $nodeType # Set the node type
                                $elementObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain # Set the message
                                $elementObject | Add-Member -NotePropertyName 'Up' -NotePropertyValue $transportNodeStatus.up_count # Set the up count
                                $elementObject | Add-Member -NotePropertyName 'Down' -NotePropertyValue $transportNodeStatus.down_count # Set the down count
                                $elementObject | Add-Member -NotePropertyName 'Degraded' -NotePropertyValue $transportNodeStatus.degraded_count # Set the degraded count
                                $elementObject | Add-Member -NotePropertyName 'Unknown' -NotePropertyValue $transportNodeStatus.unknown_count # Set the unknown count
                                $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert # Set the alert
                                $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue "$message" # Set the message
                                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                    if ($elementObject.alert -eq 'RED') {
                                        $customObject += $elementObject
                                    }
                                }
                                else {
                                    $customObject += $elementObject
                                }
                            }
                        }
                        $customObject | Sort-Object Domain, Resource, Element                
                    }
                }
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-NsxtTransportNodeStatus

Function Request-NsxtTier0BgpStatus {
    <#
        .SYNOPSIS
        Returns the BGP status for all Tier-0 gateways managed by the NSX Local Manager cluster.

        .DESCRIPTION
        The Request-NsxtTier0BgpStatus cmdlet returns the BGP status for all Tier-0 gateways managed by the NSX Manager
        cluster. The cmdlet connects to the NSX Local Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the NSX Local Manager cluster
        - Gathers the details for the NSX Local Manager cluster
        - Collects the BGP status for all Tier-0s managed by the NSX Local Manager cluster

        .EXAMPLE
        Request-NsxtTier0BgpStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return the BGP status for all Tier-0 gateways managed by the NSX Local Manager cluster that is managed by SDDC Manager for a workload domain.

        .EXAMPLE
        Request-NsxtTier0BgpStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
        This example will return the BGP status for all Tier-0 gateways managed by the NSX Local Manager cluster that is managed by SDDC Manager for a workload domain but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfNsxDetails = Get-NsxtServerDetail -fqdn $server -username $user -password $pass -domain $domain)) {
                    if (Test-NSXTConnection -server $vcfNsxDetails.fqdn) {
                        if (Test-NSXTAuthentication -server $vcfNsxDetails.fqdn -user ($vcfNsxDetails.adminUser | Select-Object -first 1) -pass ($vcfNsxDetails.adminPass | Select-Object -first 1)) {
                            $customObject = New-Object System.Collections.ArrayList
                            $tier0s = Get-NsxtTier0Gateway
                            foreach ($tier0 in $tier0s) {
                                $bgpStatus = Get-NsxtTier0BgpStatus -id $tier0.id | Where-Object {$_.type -eq 'USER'}
                                $localAsn = (Get-NsxtTier0LocaleServiceBgp -id $tier0.id).local_as_num
                                foreach ($element in $bgpStatus) {
                                    if ($element.connection_state -eq 'ESTABLISHED') {  
                                        $alert = "GREEN"
                                        $message = "BGP is established."
                                    } else {
                                        $alert = "RED"
                                        $message = "BGP is not established. Please check the configuration."
                                    }
                                    $elementObject = New-Object -TypeName psobject
                                    # NSX Tier-0 BGP Status Properties
                                    $elementObject | Add-Member -NotePropertyName 'NSX Manager' -NotePropertyValue $vcfNsxDetails.fqdn
                                    $elementObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain
                                    $elementObject | Add-Member -NotePropertyName 'Tier-0 ID' -NotePropertyValue $tier0.id
                                    $elementObject | Add-Member -NotePropertyName 'Connection' -NotePropertyValue $element.connection_state
                                    $elementObject | Add-Member -NotePropertyName 'Source Address' -NotePropertyValue $element.source_address
                                    $elementObject | Add-Member -NotePropertyName 'Neighbor Address' -NotePropertyValue $element.neighbor_address
                                    $elementObject | Add-Member -NotePropertyName 'Local ASN' -NotePropertyValue $localAsn
                                    $elementObject | Add-Member -NotePropertyName 'Remote ASN' -NotePropertyValue $element.remote_as_number
                                    $elementObject | Add-Member -NotePropertyName 'Hold' -NotePropertyValue $element.hold_time
                                    $elementObject | Add-Member -NotePropertyName 'Keep Alive ' -NotePropertyValue $element.keep_alive_interval
                                    $elementObject | Add-Member -NotePropertyName 'Established Time (sec)' -NotePropertyValue $element.time_since_established
                                    $elementObject | Add-Member -NotePropertyName 'Total In Prefix' -NotePropertyValue $element.total_in_prefix_count
                                    $elementObject | Add-Member -NotePropertyName 'Total Out Prefix' -NotePropertyValue $element.total_out_prefix_count
                                    $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
                                    $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $message
                                    
                                    if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                        if ($element.connection_state -ne 'ESTABLISHED') {
                                            $customObject += $elementObject
                                        }
                                    } else {
                                        $customObject += $elementObject
                                    }  
                                }
                            }
                            $customObject | Sort-Object 'NSX Manager', 'Domain', 'Tier-0 ID', 'Source Address'             
                        }
                    }
                }
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-NsxtTier0BgpStatus

##########################################  E N D   O F   F U N C T I O N S  ##########################################
#######################################################################################################################


#######################################################################################################################
###################################  S Y S T E M   A L E R T   F U N C T I O N S   ####################################

Function Publish-EsxiAlert {
    <#
        .SYNOPSIS
        Publish system alerts/alarms from ESXi hosts in a vCenter Server instance managed by SDDC Manager.

        .DESCRIPTION
        The Publish-EsxiAlert cmdlet returns all alarms from ESXi hosts managed by SDDC Manager.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Server instance
        - Validates the authentication to vCenter Server with credentials from SDDC Manager
        - Collects the alerts from all ESXi hosts in vCenter Server instance

        .EXAMPLE
        Publish-EsxiAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will return alarms from all ESXi hosts in vCenter Server managed by SDDC Manager for a all workload domains.

        .EXAMPLE
        Publish-EsxiAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -failureOnly
        This example will return alarms from all ESXi hosts in vCenter Server managed by SDDC Manager for a all workload domains but only for the failed items.

        .EXAMPLE
        Publish-EsxiAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will return alarms from all ESXi hosts in vCenter Server managed by SDDC Manager for a workload domain names sfo-w01.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )
    
    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $allWorkloadDomains = Get-VCFWorkloadDomain
                $allAlertObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                    if ($PsBoundParameters.ContainsKey('allDomains')) {
                        foreach ($domain in $allWorkloadDomains ) {
                            $esxiSystemAlert = Request-EsxiAlert -server $server -user $user -pass $pass $domain.name -failureOnly; $allAlertObject += $esxiSystemAlert
                        }
                    } else {
                        $esxiSystemAlert = Request-EsxiAlert -server $server -user $user -pass $pass -domain $workloadDomain -failureOnly; $allAlertObject += $esxiSystemAlert
                    }
                }
                else {
                    if ($PsBoundParameters.ContainsKey('allDomains')) { 
                        foreach ($domain in $allWorkloadDomains ) {
                            $esxiSystemAlert = Request-EsxiAlert -server $server -user $user -pass $pass $domain.name; $allAlertObject += $esxiSystemAlert
                        }
                    } else {
                        $esxiSystemAlert = Request-EsxiAlert -server $server -user $user -pass $pass -domain $workloadDomain; $allAlertObject += $esxiSystemAlert
                    }
                }

                if ($allAlertObject.Count -eq 0) {
                    $addNoIssues = $true 
                }
                if ($addNoIssues) {
                    $allAlertObject = $allAlertObject | Sort-Object Component, Resource, Domain | ConvertTo-Html -Fragment -PreContent '<a id="alert-esxi"></a><h3>ESXi Host Alert</h3>' -PostContent '<p>No issues found.</p>' 
                } else {
                    $allAlertObject = $allAlertObject | Sort-Object Component, Resource, Domain | ConvertTo-Html -Fragment -PreContent '<a id="alert-esxi"></a><h3>ESXi Host Alerts</h3>' -As Table
                }
                $allAlertObject = Convert-CssClass -htmldata $allAlertObject
                $allAlertObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-EsxiAlert

Function Publish-NsxtAlert {
    <#
        .SYNOPSIS
        Publish system alerts/alarms from a NSX Manager cluster managed by SDDC Manager.

        .DESCRIPTION
        The Publish-NsxtAlert cmdlet returns all alarms from NSX Manager cluster.
        The cmdlet connects to the NSX Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the NSX Manager cluster
        - Validates that network connectivity is available to the vCenter Server instance
        - Gathers the details for the NSX Manager cluster
        - Collects the alerts

        .EXAMPLE
        Publish-NsxtAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will return alarms from all NSX Manager clusters managed by SDDC Manager for a all workload domains.

        .EXAMPLE
        Publish-NsxtAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -failureOnly
        This example will return alarms from all NSX Manager clusters managed by SDDC Manager for a all workload domains but only for the failed items.

        .EXAMPLE
        Publish-NsxtAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will return alarms from the NSX Manager cluster managed by SDDC Manager for a workload domain named sfo-w01.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )
    
    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $allWorkloadDomains = Get-VCFWorkloadDomain
                $allAlertObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                    if ($PsBoundParameters.ContainsKey("allDomains")) {
                        foreach ($domain in $allWorkloadDomains ) {
                            $nsxtSystemAlert = Request-NsxtAlert -server $server -user $user -pass $pass -domain $domain.name -failureOnly; $allAlertObject += $nsxtSystemAlert
                        }
                    } else {
                        $nsxtSystemAlert = Request-NsxtAlert -server $server -user $user -pass $pass -domain $workloadDomain -failureOnly; $allAlertObject += $nsxtSystemAlert
                    }
                } else {
                    if ($PsBoundParameters.ContainsKey("allDomains")) { 
                        foreach ($domain in $allWorkloadDomains ) {
                            $nsxtSystemAlert = Request-NsxtAlert -server $server -user $user -pass $pass -domain $domain.name; $allAlertObject += $nsxtSystemAlert
                        }
                    } else {
                        $nsxtSystemAlert = Request-NsxtAlert -server $server -user $user -pass $pass -domain $workloadDomain; $allAlertObject += $nsxtSystemAlert
                    }
                }

                if ($allAlertObject.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $allAlertObject = $allAlertObject | Sort-Object Component, Resource, Domain | ConvertTo-Html -Fragment -PreContent '<a id="alert-nsx"></a><h3>NSX-T Data Center Alert</h3>' -PostContent '<p>No issues found.</p>' 
                } else {
                    $allAlertObject = $allAlertObject | Sort-Object Component, Resource, Domain | ConvertTo-Html -Fragment -PreContent '<a id="alert-nsx"></a><h3>NSX-T Data Center Alerts</h3>' -As Table
                }
                $allAlertObject = Convert-CssClass -htmldata $allAlertObject
                $allAlertObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-NsxtAlert

Function Publish-VcenterAlert {
    <#
        .SYNOPSIS
        Returns alarms from vCenter Server managed by SDDC Manager.

        .DESCRIPTION
        The Publish-VcenterAlert cmdlet returns all alarms from vCenter Server managed by SDDC Manager.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Server instance
        - Validates the authentication to vCenter Server with credentials from SDDC Manager
        - Collects the alerts from vCenter Server

        .EXAMPLE
        Publish-VcenterAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will return alarms from a vCenter Server managed by SDDC Manager for all workload domains.

        .EXAMPLE
        Publish-VcenterAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will return alarms from a vCenter Server managed by SDDC Manager for all workload domains but only for the failed items.

        .EXAMPLE
        Publish-VcenterAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return alarms from a vCenter Server managed by SDDC Manager for a workload domain named sfo-w01.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )
    
    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $allWorkloadDomains = Get-VCFWorkloadDomain
                $allAlertObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                    if ($PsBoundParameters.ContainsKey('allDomains')) {
                        foreach ($domain in $allWorkloadDomains ) {
                            $vcenterSystemAlert = Request-VcenterAlert -server $server -user $user -pass $pass $domain.name -failureOnly; $allAlertObject += $vcenterSystemAlert
                        }
                    } else {
                        $vcenterSystemAlert = Request-VcenterAlert -server $server -user $user -pass $pass -domain $workloadDomain -failureOnly; $allAlertObject += $vcenterSystemAlert
                    }
                } else {
                    if ($PsBoundParameters.ContainsKey('allDomains')) { 
                        foreach ($domain in $allWorkloadDomains ) {
                            $vcenterSystemAlert = Request-VcenterAlert -server $server -user $user -pass $pass $domain.name; $allAlertObject += $vcenterSystemAlert
                        }
                    } else {
                        $vcenterSystemAlert = Request-VcenterAlert -server $server -user $user -pass $pass -domain $workloadDomain; $allAlertObject += $vcenterSystemAlert
                    }
                }

                if ($allAlertObject.Count -eq 0) {
                    $addNoIssues = $true 
                }
                if ($addNoIssues) {
                    $allAlertObject = $allAlertObject | Sort-Object Component, Resource, Domain | ConvertTo-Html -Fragment -PreContent '<a id="alert-vcenter"></a><h3>vCenter Server Alert</h3>' -PostContent '<p>No issues found.</p>' 
                } else {
                    $allAlertObject = $allAlertObject | Sort-Object Component, Resource, Domain | ConvertTo-Html -Fragment -PreContent '<a id="alert-vcenter"></a><h3>vCenter Server Alerts</h3>' -As Table
                }
                $allAlertObject = Convert-CssClass -htmldata $allAlertObject
                $allAlertObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-VcenterAlert

Function Publish-VsanAlert {
    <#
        .SYNOPSIS
        RPublish the vSAN Healthcheck alarms from a vCenter Server instance.

        .DESCRIPTION
        The Publish-VsanAlert cmdlet returns vSAN Healthcheck alarms from vCenter Server managed by SDDC Manager.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Server instance
        - Validates the authentication to vCenter Server with credentials from SDDC Manager
        - Collects the vSAN Healthcheck alarms from vCenter Server

        .EXAMPLE
        Publish-VsanAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will return vSAN Healthcheck alarms for all vCenter Server instances managed by SDDC Manager for a workload domain.

        .EXAMPLE
        Publish-VsanAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -failureOnly
        This example will return vSAN Healthcheck alarms for all vCenter Server instances managed by SDDC Manager for a workload domain but only failed items.

        .EXAMPLE
        Publish-VsanAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will return vSAN Healthcheck alarms of a vCenter Server managed by SDDC Manager for a workload domain named sfo-w01.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )
    
    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $allWorkloadDomains = Get-VCFWorkloadDomain
                $allAlertObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                    if ($PsBoundParameters.ContainsKey('allDomains')) {
                        foreach ($domain in $allWorkloadDomains ) {
                            $vsanSystemAlert = Request-VsanAlert -server $server -user $user -pass $pass $domain.name -failureOnly; $allAlertObject += $vsanSystemAlert
                        }
                    } else {
                        $vsanSystemAlert = Request-VsanAlert -server $server -user $user -pass $pass -domain $workloadDomain -failureOnly; $allAlertObject += $vsanSystemAlert
                    }
                } else {
                    if ($PsBoundParameters.ContainsKey('allDomains')) { 
                        foreach ($domain in $allWorkloadDomains ) {
                            $vsanSystemAlert = Request-VsanAlert -server $server -user $user -pass $pass $domain.name; $allAlertObject += $vsanSystemAlert
                        }
                    } else {
                        $vsanSystemAlert = Request-VsanAlert -server $server -user $user -pass $pass -domain $workloadDomain; $allAlertObject += $vsanSystemAlert
                    }
                }

                if ($allAlertObject.Count -eq 0) {
                    $addNoIssues = $true 
                }
                if ($addNoIssues) {
                    $allAlertObject = $allAlertObject | Sort-Object Component, Resource, Domain | ConvertTo-Html -Fragment -PreContent '<a id="alert-vsan"></a><h3>vSAN Alert</h3>' -PostContent '<p>No issues found.</p>' 
                } else {
                    $allAlertObject = $allAlertObject | Sort-Object Component, Resource, Domain | ConvertTo-Html -Fragment -PreContent '<a id="alert-vsan"></a><h3>vSAN Alerts</h3>' -As Table
                }
                $allAlertObject = Convert-CssClass -htmldata $allAlertObject
                $allAlertObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-VsanAlert

Function Request-NsxtAlert {
    <#
        .SYNOPSIS
        Returns alarms from an NSX Manager cluster.

        .DESCRIPTION
        The Request-NsxtAlert cmdlet returns all alarms from NSX Manager cluster.
        The cmdlet connects to the NSX-T Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the NSX-T Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Gathers the details for the NSX Manager cluster
        - Collects the alerts

        .EXAMPLE
        Request-NsxtAlert -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-w01
        This example will return alarms of an NSX Manager cluster managed by SDDC Manager for a workload domain.
        
        .EXAMPLE
        Request-NsxtAlert -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-w01 -failureOnly
        This example will return alarms of an NSX Manager cluster managed by SDDC Manager for a workload domain but only for the failed items

        .EXAMPLE
        Request-NsxtAlert -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-w01 -html
        This example will return alarms of an NSX Manager cluster managed by SDDC Manager for a workload domain and outputs to html.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    if (Test-VCFConnection -server $server) {
        if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            if (($vcfNsxDetails = Get-NsxtServerDetail -fqdn $server -username $user -password $pass -domain $domain)) {
                if (Test-NSXTConnection -server $vcfNsxDetails.fqdn) {
                    if (Test-NSXTAuthentication -server $vcfNsxDetails.fqdn -user ($vcfNsxDetails.adminUser | Select-Object -first 1) -pass ($vcfNsxDetails.adminPass | Select-Object -first 1)) {
                        $nsxtAlarms = Get-NsxtAlarm -fqdn $vcfNsxDetails.fqdn # Get the NSX-T alarms
                        $customObject = New-Object System.Collections.ArrayList
                        # TODO: Define the YELLOW alert based on Status and Severity
                        foreach ($alarm in $nsxtAlarms.results) {
                            if ($alarm.status -eq "RESOLVED") {
                                $alert = "GREEN"
                            } else {
                                $alert = "RED"
                            }
                            $elementObject = New-Object -TypeName psobject
                            $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue 'NSX Manager' # Set the component name
                            $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $vcfNsxDetails.fqdn # Set the resource name
                            $elementObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain # Set the domain
                            $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert # Set the alert
                            # Alarm properties
                            $elementObject | Add-Member -NotePropertyName 'Feature Name' -NotePropertyValue $alarm.feature_name # Set the feature_name
                            $elementObject | Add-Member -NotePropertyName 'Event Type' -NotePropertyValue $alarm.event_type # Set the event_type
                            $elementObject | Add-Member -NotePropertyName 'Description' -NotePropertyValue $alarm.description # Set the description
                            $elementObject | Add-Member -NotePropertyName 'Status' -NotePropertyValue $alarm.status # Set the status
                            $elementObject | Add-Member -NotePropertyName 'Severity' -NotePropertyValue $alarm.severity # Set the severity
                            $elementObject | Add-Member -NotePropertyName 'Node Name' -NotePropertyValue $alarm.node_display_name # Set the node_display_name
                            $elementObject | Add-Member -NotePropertyName 'Node IP Address' -NotePropertyValue "$($alarm.node_ip_addresses)" # Set the node_ip_addresses array converted to sting
                            
                            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                    $customObject += $elementObject
                                }
                            } else {
                                $customObject += $elementObject
                            }
                        }
                        # Return the structured data to the console or format using HTML CSS Styles
                        if ($PsBoundParameters.ContainsKey('html')) { 
                            $customObject = $customObject | Sort-Object Component, Resource, Domain, Status | ConvertTo-Html -Fragment -PreContent '<h2>NSX-T Data Center Alarms</h2>' -As Table
                            $customObject
                        } else {
                            $customObject | Sort-Object Component, Resource, Domain, Status
                        }
                        
                    }
                }
            }
        }
    }
}
Export-ModuleMember -Function Request-NsxtAlert

Function Request-VsanAlert {
    <#
        .SYNOPSIS
        Returns vSAN Healthcheck alarms from a vCenter Server instance.

        .DESCRIPTION
        The Request-VsanAlert cmdlet returns vSAN Healthcheck alarms from vCenter Server managed by SDDC Manager.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Server instance
        - Validates the authentication to vCenter Server with credentials from SDDC Manager
        - Collects the vSAN Healthcheck alarms from vCenter Server

        .EXAMPLE
        Request-VsanAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return vSAN Healthcheck alarms of a vCenter Server managed by SDDC Manager for a workload domain.

        .EXAMPLE
        Request-VsanAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
        This example will return vSAN Healthcheck alarms of a vCenter Server managed by SDDC Manager for a workload domain but only for the failed items.

        .EXAMPLE
        Request-VsanAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -html
        This example will return vSAN Healthcheck alarms of a vCenter Server managed by SDDC Manager for a workload domain and outputs to html.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html
    )

    if (Test-VCFConnection -server $server) {
        if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain)) {
                if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                    if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                        foreach ($cluster in Get-Cluster -Server $vcfVcenterDetails.fqdn ) {
                            $vsanAlarms = Get-VsanHealthTest -cluster $cluster
                            $customObject = New-Object System.Collections.ArrayList
                            foreach ($vsanAlarm in $vsanAlarms) {
                                $elementObject = New-Object -TypeName psobject
                                $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue 'vSAN'
                                $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $vcfVcenterDetails.fqdn
                                $elementObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain
                                $elementObject | Add-Member -NotePropertyName 'Cluster' -NotePropertyValue $cluster
                                # Alarm properties
                                $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $vsanAlarm.TestHealth
                                $elementObject | Add-Member -NotePropertyName 'GroupName' -NotePropertyValue $vsanAlarm.GroupName
                                $elementObject | Add-Member -NotePropertyName 'TestName' -NotePropertyValue $vsanAlarm.TestName
                                
                                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                    if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                        $customObject += $elementObject
                                    }
                                } else {
                                    $customObject += $elementObject
                                }
                            }
                        }
                        Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                        
                        # Return the structured data to the console or format using HTML CSS Styles
                        if ($PsBoundParameters.ContainsKey('html')) { 
                            $customObject = $customObject | Sort-Object Component, Resource, Domain, Cluster, Alert | ConvertTo-Html -Fragment -PreContent '<h2>vSAN Alarms</h2>' -As Table
                            $customObject
                        } else {
                            $customObject | Sort-Object Component, Resource, Domain, Cluster, Alert
                        }
                        
                    }
                }
            }
        }
    }
}
Export-ModuleMember -Function Request-VsanAlert

Function Request-VcenterAlert {
    <#
        .SYNOPSIS
        Returns alarms from vCenter Server managed by SDDC Manager.

        .DESCRIPTION
        The Request-VcenterAlert cmdlet returns all alarms from vCenter Server managed by SDDC Manager.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Server instance
        - Validates the authentication to vCenter Server with credentials from SDDC Manager
        - Collects the alerts from vCenter Server

        .EXAMPLE
        Request-VcenterAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return alarms of a vCenter Server managed by SDDC Manager for a workload domain named sfo-w01.
        
        .EXAMPLE
        Request-VcenterAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -filterOut hostOnly
        This example will return alarms from ESXi hosts of a vCenter Server managed by SDDC Manager for a workload domain named sfo-w01.

        .EXAMPLE
        Request-VcenterAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
        This example will return alarms from vSAN clusters of a vCenter Server managed by SDDC Manager for a workload domain but only for the failed items.

        .EXAMPLE
        Request-VcenterAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -html
        This example will return alarms of a vCenter Server managed by SDDC Manager for a workload domain named sfo-w01 and output in html format.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
<<<<<<< HEAD
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
=======
        [Parameter (Mandatory = $false)] [ValidateSet("hostOnly","vsanOnly")][ValidateNotNullOrEmpty()] [String]$filterOut,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html
>>>>>>> 5ee7fec (Enchace Request-VcenterAlert)
    )

    if (Test-VCFConnection -server $server) {
        if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain)) {
                if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                    if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                        $vcenterAlarms = Get-VcenterTriggeredAlarm -server $vcfVcenterDetails.fqdn # Get the vCenter alarms
                        $customObject = New-Object System.Collections.ArrayList
                        foreach ($alarm in $vcenterAlarms) {
                            [String]$alert = $alarm.Status
                            $alert = $alert.ToUpper()
                            $elementObject = New-Object -TypeName psobject
                            $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue 'vCenter Server'
                            $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $vcfVcenterDetails.fqdn
                            $elementObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain
                            $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
                            # Alarm properties
                            $elementObject | Add-Member -NotePropertyName 'Entity Type' -NotePropertyValue $alarm.EntityType
                            $elementObject | Add-Member -NotePropertyName 'Alarm' -NotePropertyValue $alarm.Alarm
                            $elementObject | Add-Member -NotePropertyName 'Time' -NotePropertyValue $alarm.Time
                            $elementObject | Add-Member -NotePropertyName 'Acknowledged' -NotePropertyValue $alarm.Acknowledged 
                            $elementObject | Add-Member -NotePropertyName 'Acknowledged By' -NotePropertyValue $alarm.AckBy
                            $elementObject | Add-Member -NotePropertyName 'Acknowledged Time' -NotePropertyValue $alarm.AcknowledgedTime
                            
<<<<<<< HEAD
                            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                if ((($elementObject.alert -eq 'RED') -or ($elementObject.Alert -eq 'YELLOW')) -and !($elementObject.Acknowledged)) {
=======
                            $addToCustomObject = $false

                            switch ($filterOut) {
                                "hostOnly" {
                                    if ($elementObject.EntityType -eq "HostSystem") {
                                        $addToCustomObject = $true
                                    }
                                    Break
                                }
                                "vsanOnly" {
                                    if (($elementObject.EntityType -eq "ClusterComputeResource") -and ($elementObject.Alarm -like "vsan*")) {
                                        $addToCustomObject = $true
                                    }
                                    Break
                                }
                                default {
                                    $addToCustomObject = $true
                                }
                            }
                            if ($addToCustomObject){
                                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                    if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                        $customObject += $elementObject
                                    }
<<<<<<< HEAD
                                }
                                else {
>>>>>>> 5ee7fec (Enchace Request-VcenterAlert)
=======
                                } else {
>>>>>>> 020b166 (Adjust Alert Output on Report)
                                    $customObject += $elementObject
                                }
                            }
                            
                        }
                        Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null

                        # Return the structured data to the console or format using HTML CSS Styles
                        if ($PsBoundParameters.ContainsKey('html')) { 
                            $customObject = $customObject | Sort-Object Component, Resource, Domain, 'Entity Type', Alert | ConvertTo-Html -Fragment -PreContent '<h2>vCenter Server Alarms</h2>' -As Table
                            $customObject
                        } else {
                            $customObject | Sort-Object Component, Resource, Domain, 'Entity Type', Alert
                        }
                    }
                }
            }
        }
    }
}
Export-ModuleMember -Function Request-VcenterAlert

Function Request-EsxiAlert {
    <#
        .SYNOPSIS
        Returns Alarms from all ESXi hosts in vCenter Server instance.

        .DESCRIPTION
        The Request-EsxiAlert cmdlet returns all alarms from all ESXi hosts in vCenter Server managed by SDDC Manager.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Server instance
        - Validates the authentication to vCenter Server with credentials from SDDC Manager
        - Collects the alerts from all ESXi hosts in vCenter Server instance

        .EXAMPLE
        Request-EsxiAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return alarms from all ESXi hosts in vCenter Server managed by SDDC Manager for a workload domain sfo-w01.

        .EXAMPLE
        Request-EsxiAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass  VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
        This example will return alarms from all ESXi hosts in vCenter Server managed by SDDC Manager for a workload domain sfo-w01 but only for the failed items.

        .EXAMPLE
        Request-EsxiAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -html
        This example will return alarms from all ESXi hosts in vCenter Server managed by SDDC Manager for a workload domain sfo-w01 and output in html format
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    if (Test-VCFConnection -server $server) {
        if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain)) {
                if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                    if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                        $customObject = New-Object System.Collections.ArrayList
                        foreach ($allHosts in Get-VMHost -Server $vcfVcenterDetails.fqdn) {
                            $esxiAlarms = Get-EsxiAlert -host $allHosts # Get the ESXi alarms
                            foreach ($alarm in $esxiAlarms) {
                                [String]$alert = $alarm.Status
                                $alert = $alert.ToUpper()
                                $elementObject = New-Object -TypeName psobject
                                $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue 'ESXi Host'
                                $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $vcfVcenterDetails.fqdn
                                $elementObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain
                                $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
                                # Alarm properties
                                $elementObject | Add-Member -NotePropertyName 'Entity' -NotePropertyValue $alarm.Entity
                                $elementObject | Add-Member -NotePropertyName 'Alarm' -NotePropertyValue $alarm.Alarm
                                $elementObject | Add-Member -NotePropertyName 'Time' -NotePropertyValue $alarm.Time
                                $elementObject | Add-Member -NotePropertyName 'Acknowledged' -NotePropertyValue $alarm.Acknowledged 
                                $elementObject | Add-Member -NotePropertyName 'Acknowledged By' -NotePropertyValue $alarm.AckBy
                                $elementObject | Add-Member -NotePropertyName 'Acknowledged Time' -NotePropertyValue $alarm.AcknowledgedTime
                                if ($PsBoundParameters.ContainsKey("failureOnly")) {
                                    if ((($elementObject.alert -eq 'RED') -or ($elementObject.Alert -eq 'YELLOW')) -and !($elementObject.Acknowledged)) {
                                        $customObject += $elementObject
                                    }
                                } else {
                                    $customObject += $elementObject
                                }
                            }
                        }
                        Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null

                        # Return the structured data to the console or format using HTML CSS Styles
                        if ($PsBoundParameters.ContainsKey("html")) { 
                            $customObject = $customObject | Sort-Object Component, Resource, Domain, Entity, Alert | ConvertTo-Html -Fragment -PreContent '<h2>ESXi Alarms</h2>' -As Table
                            $customObject
                        } else {
                            $customObject | Sort-Object Component, Resource, Domain, Entity, Alert
                        }
                    }
                }
            }
        }
    }
}
Export-ModuleMember -Function Request-EsxiAlert

##########################################  E N D   O F   F U N C T I O N S  ##########################################
#######################################################################################################################


#######################################################################################################################
#################################  C O N F I G U R A T I O N   F U N C T I O N S   ####################################

Function Publish-EsxiCoreDumpConfig {
    <#
		.SYNOPSIS
        Generates an ESXi core dump configuration report.

        .DESCRIPTION
        The Publish-EsxiCoreDumpConfig cmdlet generates an ESXi core dump report for a workload domain. The cmdlet
        connects to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Generates an ESXi core dump report for all ESXi hosts in a workload domain

        .EXAMPLE
        Publish-EsxiCoreDumpConfig -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -alldomains
        This example generates an ESXi core dump report for all ESXi hosts across the VMware Cloud Foundation instance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific--WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $allHostObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey("allDomains")) {
                    $allWorkloadDomains = Get-VCFWorkloadDomain
                    $domainHostObject = New-Object System.Collections.ArrayList
                    foreach ($domain in $allWorkloadDomains) {
                        if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain.name)) {
                            if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                                if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                                    $coreDumpObject = New-Object -TypeName psobject
                                    $esxiHosts = Get-VMHost 
                                    Foreach ($esxiHost in $esxiHosts) {
                                        $coreDumpObject = New-Object -TypeName psobject
                                        $esxcli = Get-EsxCli -VMhost $esxiHost.Name -V2
                                        $coreDumpConfig = $esxcli.system.coredump.partition.get.invoke()
                                        $coreDumpObject | Add-Member -notepropertyname 'Domain' -notepropertyvalue $domain.name
                                        $coreDumpObject | Add-Member -notepropertyname 'Host' -notepropertyvalue $esxiHost.Name
                                        $coreDumpObject | Add-Member -notepropertyname 'Active Core Dump' -notepropertyvalue $coreDumpConfig.Active
                                        $coreDumpObject | Add-Member -notepropertyname 'Configured Core Dump' -notepropertyvalue $coreDumpConfig.Configured
                                        $domainHostObject += $coreDumpObject 
                                    }
                                }
                            }
                        }
                        Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                    }
                    $allHostObject += $domainHostObject
                } else {
                    if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $workloadDomain)) {
                        if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                            if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                                $coreDumpObject = New-Object -TypeName psobject
                                $esxiHosts = Get-VMHost 
                                Foreach ($esxiHost in $esxiHosts) {
                                    $coreDumpObject = New-Object -TypeName psobject
                                    $esxcli = Get-EsxCli -VMhost $esxiHost.Name -V2
                                    $coreDumpConfig = $esxcli.system.coredump.partition.get.invoke()
                                    $coreDumpObject | Add-Member -notepropertyname 'Domain' -notepropertyvalue $workloadDomain
                                    $coreDumpObject | Add-Member -notepropertyname 'Host' -notepropertyvalue $esxiHost.Name
                                    $coreDumpObject | Add-Member -notepropertyname 'Active Core Dump' -notepropertyvalue $coreDumpConfig.Active
                                    $coreDumpObject | Add-Member -notepropertyname 'Configured Core Dump' -notepropertyvalue $coreDumpConfig.Configured
                                    $allHostObject += $coreDumpObject
                                }
                            }
                        }
                        Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                    }
                }
                if ($PsBoundParameters.ContainsKey('html')) {
                    $allHostObject = $allHostObject | Sort-Object Domain, Host | ConvertTo-Html -Fragment -PreContent '<a id="esxi-coredmp"></a><h3>ESXi Core Dump Configuration</h3>' -As Table
                }
                $allHostObject = Convert-CssClass -htmldata $allHostObject
                $allHostObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-EsxiCoreDumpConfig

##########################################  E N D   O F   F U N C T I O N S  ##########################################
#######################################################################################################################


#######################################################################################################################
###############################  P A S S W O R D   P O L I C Y   F U N C T I O N S   ##################################

Function Publish-EsxiPolicy {
    <#
        .SYNOPSIS
        Publish password policy for ESXi hosts in a vCenter Server instance managed by SDDC Manager.

        .DESCRIPTION
        The Publish-EsxiPolicy cmdlet returns password policy from ESXi hosts managed by SDDC Manager.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Server instance
        - Validates the authentication to vCenter Server with credentials from SDDC Manager
        - Collects password policy from all ESXi hosts in vCenter Server instance

        .EXAMPLE
        Publish-EsxiPolicy -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will return password policy from all ESXi hosts in vCenter Server managed by SDDC Manager for a all workload domains.

        .EXAMPLE
        Publish-EsxiPolicy -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will return password policy from all ESXi hosts in vCenter Server managed by SDDC Manager for a workload domain names sfo-w01.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain
    )
    
    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $allEsxiPolicyObject = New-Object System.Collections.ArrayList
                $allEsxiPasswordPolicyObject = New-Object System.Collections.ArrayList
                $allEsxiLockoutPolicyObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('allDomains')) {
                    $allWorkloadDomains = Get-VCFWorkloadDomain
                    foreach ($domain in $allWorkloadDomains ) {
                        $esxiPasswordPolicy = Request-EsxiPasswordPolicy -server $server -user $user -pass $pass -domain $domain.name; $allEsxiPasswordPolicyObject += $esxiPasswordPolicy
                        $esxiLockoutPolicy = Request-EsxiLockoutPolicy -server $server -user $user -pass $pass -domain $domain.name; $allEsxiLockoutPolicyObject += $esxiLockoutPolicy
                    }
                }
                else {
                    $esxiPasswordPolicy = Request-EsxiPasswordPolicy -server $server -user $user -pass $pass -domain $workloadDomain; $allEsxiPasswordPolicyObject += $esxiPasswordPolicy
                    $esxiLockoutPolicy = Request-EsxiLockoutPolicy -server $server -user $user -pass $pass -domain $workloadDomain; $allEsxiLockoutPolicyObject += $esxiLockoutPolicy
                }
                $allEsxiPasswordPolicyObject = $allEsxiPasswordPolicyObject | Sort-Object Cluster, 'ESXi FQDN' | ConvertTo-Html -Fragment -PreContent '<a id="policy-password-esxi"></a><h3>ESXi Password Policy</h3>' -As Table
                $allEsxiPasswordPolicyObject = Convert-CssClass -htmldata $allEsxiPasswordPolicyObject
                $allEsxiLockoutPolicyObject = $allEsxiLockoutPolicyObject | Sort-Object Cluster, 'ESXi FQDN' | ConvertTo-Html -Fragment -PreContent '<a id="policy-lockout-esxi"></a><h3>ESXi Lockout Policy</h3>' -As Table
                $allEsxiLockoutPolicyObject = Convert-CssClass -htmldata $allEsxiLockoutPolicyObject
                $allEsxiPolicyObject += $allEsxiPasswordPolicyObject
                $allEsxiPolicyObject += $allEsxiLockoutPolicyObject
                $allEsxiPolicyObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-EsxiPolicy

Function Request-EsxiPasswordPolicy {
    <#
        .SYNOPSIS
        Returns ESXi Password Policy.

        .DESCRIPTION
        The Request-EsxiPasswordPolicy cmdlet returns the Password Policy for ESXi hosts managed by SDDC Manager.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Server instance
        - Collects the Password Policy configuration for each ESXi host

        .EXAMPLE
        Request-EsxiPasswordPolicy -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return the Password Policy configuration for ESXi hosts managed by SDDC Manager for a workload domain.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain)) {
                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            if (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $domain }) {
                                $clusterObject = New-Object System.Collections.ArrayList
                                $esxiPasswordPolicyObject = New-Object System.Collections.ArrayList
                                $allClusters = Get-Cluster -Server $vcfVcenterDetails.fqdn
                                foreach ($cluster in $allClusters) {
                                    $allHosts = Get-Cluster $cluster.name -Server $vcfVcenterDetails.fqdn | Get-VMHost -Server $vcfVcenterDetails.fqdn
                                    foreach ($esxiHost in $allHosts) {
                                        $passwordPolicy = Get-VMHost -name $esxiHost | Where-Object { $_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"} | Get-AdvancedSetting | Where-Object { $_.Name -eq "Security.PasswordQualityControl" }
                                        if ($passwordPolicy) {
                                            $passwordPolicy.Value | Select-String -Pattern "^retry=(\d+)\s+min=(.+),(.+),(.+),(.+),(.+)" | Foreach-Object {$PasswdPolicyRetryValue, $PasswdPolicyMinValue1, $PasswdPolicyMinValue2, $PasswdPolicyMinValue3, $PasswdPolicyMinValue4, $PasswdPolicyMinValue5 = $_.Matches[0].Groups[1..6].Value}
                                        }
                                        $hostPasswordPolicyObject = New-Object -TypeName psobject
                                        $hostPasswordPolicyObject | Add-Member -notepropertyname "Cluster" -notepropertyvalue $cluster
                                        $hostPasswordPolicyObject | Add-Member -notepropertyname "ESXi FQDN" -notepropertyvalue $esxiHost.Name
                                        $hostPasswordPolicyObject | Add-Member -notepropertyname "Lifetime (days)" -notepropertyvalue (Get-VMHost -name $esxiHost | Where-Object { $_.ConnectionState -eq "Connected" } | Get-AdvancedSetting | Where-Object { $_.Name -eq "Security.PasswordMaxDays" }).Value
                                        $hostPasswordPolicyObject | Add-Member -notepropertyname "History" -notepropertyvalue (Get-VMHost -name $esxiHost | Where-Object { $_.ConnectionState -eq "Connected" } | Get-AdvancedSetting | Where-Object { $_.Name -eq "Security.PasswordHistory" }).Value
                                        $hostPasswordPolicyObject | Add-Member -notepropertyname "Policy" -notepropertyvalue ($PasswdPolicyMinValue1 + "," + $PasswdPolicyMinValue2 + "," + $PasswdPolicyMinValue3 + "," + $PasswdPolicyMinValue4)
                                        $hostPasswordPolicyObject | Add-Member -notepropertyname "Length" -notepropertyvalue $PasswdPolicyMinValue5
                                        $esxiPasswordPolicyObject += $hostPasswordPolicyObject
                                    }
                                    $clusterObject += $esxiPasswordPolicyObject
                                }
                                Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                                $clusterObject | Sort-Object Cluster, 'ESXi FQDN'
                            } else {
                                Write-Error "Unable to find Workload Domain named ($domain) in the inventory of SDDC Manager ($server): PRE_VALIDATION_FAILED"
                            }
                        }
                    }
                }
            }
        }
    }

	Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Request-EsxiPasswordPolicy

Function Request-EsxiLockoutPolicy {
    <#
        .SYNOPSIS
        Returns ESXi Password Lockout Policy.

        .DESCRIPTION
        The Request-EsxiLockoutPolicy cmdlet returns the Password Lockout Policy for ESXi hosts managed by SDDC
        Manager. The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Server instance
        - Collects the Password Policy configuration for each ESXi host

        .EXAMPLE
        Request-EsxiLockoutPolicy -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return the Password Lockout Policy configuration for ESXi hosts managed by SDDC Manager for a workload domain.

        .EXAMPLE
        Request-EsxiLockoutPolicy -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -html
        This example will return the Password Lockout Policy configuration for ESXi hosts managed by SDDC Manager for a workload domain and output in HTML
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain)) {
                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            if (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $domain }) {
                                $clusterObject = New-Object System.Collections.ArrayList
                                $esxiLockoutPolicyObject = New-Object System.Collections.ArrayList
                                $allClusters = Get-Cluster -Server $vcfVcenterDetails.fqdn
                                foreach ($cluster in $allClusters) {
                                    $allHosts = Get-Cluster $cluster.name -Server $vcfVcenterDetails.fqdn | Get-VMHost -Server $vcfVcenterDetails.fqdn
                                    foreach ($esxiHost in $allHosts) {
                                        $hostLockoutPolicyObject = New-Object -TypeName psobject
                                        $hostLockoutPolicyObject | Add-Member -notepropertyname "Cluster" -notepropertyvalue $cluster
                                        $hostLockoutPolicyObject | Add-Member -notepropertyname "ESXi FQDN" -notepropertyvalue $esxiHost.Name
                                        $hostLockoutPolicyObject | Add-Member -notepropertyname "Failed Attempts" -notepropertyvalue (Get-VMHost -name $esxiHost | Where-Object { $_.ConnectionState -eq "Connected" } | Get-AdvancedSetting | Where-Object { $_.Name -eq "Security.AccountLockFailures" }).Value
                                        $hostLockoutPolicyObject | Add-Member -notepropertyname "Lockout Time (sec)" -notepropertyvalue (Get-VMHost -name $esxiHost | Where-Object { $_.ConnectionState -eq "Connected" } | Get-AdvancedSetting | Where-Object { $_.Name -eq "Security.AccountUnlockTime" }).Value                                        
                                        $esxiLockoutPolicyObject += $hostLockoutPolicyObject
                                    }
                                    $clusterObject += $esxiLockoutPolicyObject
                                }
                                Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                                $clusterObject | Sort-Object Cluster, 'ESXi FQDN'
                            } else {
                                Write-Error "Unable to find Workload Domain named ($domain) in the inventory of SDDC Manager ($server): PRE_VALIDATION_FAILED"
                            }
                        }
                    }
                }
            }
        }
    }
	Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Request-EsxiLockoutPolicy

Function Publish-VcenterPolicy {
    <#
        .SYNOPSIS
        Publish password policy for vCenter Server instance managed by SDDC Manager.

        .DESCRIPTION
        The Publish-VcenterPolicy cmdlet returns password policy for vCenter Server managed by SDDC Manager.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Server instance
        - Validates the authentication to vCenter Server with credentials from SDDC Manager
        - Collects password policy from all ESXi hosts in vCenter Server instance

        .EXAMPLE
        Publish-VcenterPolicy -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will return password policy for vCenter Server managed by SDDC Manager for a all workload domains.

        .EXAMPLE
        Publish-VcenterPolicy -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will return password policy for vCenter Server managed by SDDC Manager for a workload domain names sfo-w01.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain
    )
    
    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $allVcenterPolicyObject = New-Object System.Collections.ArrayList
                $allVcenterRootPasswordPolicyObject = New-Object System.Collections.ArrayList
                $allVcenterPasswordPolicyObject = New-Object System.Collections.ArrayList
                $allSsoPasswordPolicyObject = New-Object System.Collections.ArrayList
                $allSsoLockoutPolicyObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('allDomains')) {
                    $allWorkloadDomains = Get-VCFWorkloadDomain
                    foreach ($domain in $allWorkloadDomains ) {
                        $vcenterRootPasswordPolicy = Request-VcenterRootPasswordPolicy -server $server -user $user -pass $pass -domain $domain.name; $allVcenterRootPasswordPolicyObject += $vcenterRootPasswordPolicy
                        $vcenterPasswordPolicy = Request-VcenterPasswordPolicy -server $server -user $user -pass $pass -domain $domain.name; $allVcenterPasswordPolicyObject += $vcenterPasswordPolicy
                        $ssoPasswordPolicy = Request-SsoPasswordPolicy -server $server -user $user -pass $pass -domain $domain.name; $allSsoPasswordPolicyObject += $ssoPasswordPolicy
                        $ssoLockoutPolicy = Request-SsoLockoutPolicy -server $server -user $user -pass $pass -domain $domain.name; $allSsoLockoutPolicyObject += $ssoLockoutPolicy
                    }
                }
                else {
                    $vcenterRootPasswordPolicy = Request-VcenterRootPasswordPolicy -server $server -user $user -pass $pass -domain $workloadDomain; $allVcenterRootPasswordPolicyObject += $vcenterRootPasswordPolicy
                    $vcenterPasswordPolicy = Request-VcenterPasswordPolicy -server $server -user $user -pass $pass -domain $workloadDomain; $allVcenterPasswordPolicyObject += $vcenterPasswordPolicy
                    $ssoPasswordPolicy = Request-SsoPasswordPolicy -server $server -user $user -pass $pass -domain $workloadDomain; $allSsoPasswordPolicyObject += $ssoPasswordPolicy
                    $ssoLockoutPolicy = Request-SsoLockoutPolicy -server $server -user $user -pass $pass -domain $workloadDomain; $allSsoLockoutPolicyObject += $ssoLockoutPolicy
                }
                $allVcenterRootPasswordPolicyObject = $allVcenterRootPasswordPolicyObject | Sort-Object 'vCenter Server FQDN' | ConvertTo-Html -Fragment -PreContent '<a id="policy-password-vcenter-root"></a><h3>Password Policy (root)</h3>' -As Table
                $allVcenterRootPasswordPolicyObject = Convert-CssClass -htmldata $allVcenterRootPasswordPolicyObject
                $allVcenterPasswordPolicyObject = $allVcenterPasswordPolicyObject | Sort-Object 'vCenter Server FQDN' | ConvertTo-Html -Fragment -PreContent '<a id="policy-password-vcenter"></a><h3>Password Policy</h3>' -As Table
                $allVcenterPasswordPolicyObject = Convert-CssClass -htmldata $allVcenterPasswordPolicyObject
                $allSsoPasswordPolicyObject = $allSsoPasswordPolicyObject | Sort-Object 'Single Sign-On FQDN' | ConvertTo-Html -Fragment -PreContent '<a id="policy-password-sso"></a><h3>SSO Password Policy</h3>' -As Table
                $allSsoPasswordPolicyObject = Convert-CssClass -htmldata $allSsoPasswordPolicyObject
                $allSsoLockoutPolicyObject = $allSsoLockoutPolicyObject | Sort-Object 'Single Sign-On FQDN' | ConvertTo-Html -Fragment -PreContent '<a id="policy-lockout-sso"></a><h3>SSO Lockout Policy</h3>' -As Table
                $allSsoLockoutPolicyObject = Convert-CssClass -htmldata $allSsoLockoutPolicyObject
                $allVcenterPolicyObject += $allVcenterRootPasswordPolicyObject
                $allVcenterPolicyObject += $allVcenterPasswordPolicyObject
                $allVcenterPolicyObject += $allSsoPasswordPolicyObject
                $allVcenterPolicyObject += $allSsoLockoutPolicyObject
                $allVcenterPolicyObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-VcenterPolicy

Function Request-VcenterRootPasswordPolicy {
    <#
        .SYNOPSIS
        Returns vCenter Server Root Password Policy.

        .DESCRIPTION
        The Request-VcenterRootPasswordPolicy cmdlet returns the Root Password Policy for vCenter Server managed by
        SDDC Manager. The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Server instance
        - Collects the Password Policy configuration for vCenter Server

        .EXAMPLE
        Request-VcenterRootPasswordPolicy -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return the Root Password Policy configuration for vCenter Server managed by SDDC Manager for a workload domain.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $domain }) {
                    if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain)) {
                        if (Test-vSphereApiConnection -server $($vcfVcenterDetails.fqdn)) {
                            if (Test-vSphereApiAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                                Request-vSphereApiToken -fqdn $vcfVcenterDetails.fqdn -username $vcfVcenterDetails.ssoAdmin -password $vcfVcenterDetails.ssoAdminPass -admin | Out-Null
                                $customObject = New-Object System.Collections.ArrayList
                                $rootPasswordExpiry = Get-VCPasswordExpiry
                                $customObject = New-Object -TypeName psobject
                                $customObject | Add-Member -notepropertyname "vCenter Server FQDN" -notepropertyvalue $vcfVcenterDetails.fqdn
                                $customObject | Add-Member -notepropertyname "Lifetime (days)" -notepropertyvalue $rootPasswordExpiry.max_days_between_password_change
                                $customObject | Add-Member -notepropertyname "Warning (days)" -notepropertyvalue $rootPasswordExpiry.warn_days_before_password_expiration
                                $customObject | Add-Member -notepropertyname "Email" -notepropertyvalue $rootPasswordExpiry.email
                                $customObject | Add-Member -notepropertyname "Enabled" -notepropertyvalue $rootPasswordExpiry.enabled
                                $customObject | Add-Member -notepropertyname "Expires" -notepropertyvalue $rootPasswordExpiry.password_expires_at
                            }
                            $customObject | Sort-Object 'vCenter Server FQDN'
                        }
                    }
                    
                } else {
                    Write-Error "Unable to find Workload Domain named ($domain) in the inventory of SDDC Manager ($server): PRE_VALIDATION_FAILED"
                }
            }
        }
    }
	Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Request-VcenterRootPasswordPolicy

Function Request-VcenterPasswordPolicy {
    <#
        .SYNOPSIS
        Returns vCenter Server Password Policy.

        .DESCRIPTION
        The Request-VcenterPasswordPolicy cmdlet returns the Password Policy for vCenter Server managed by
        SDDC Manager. The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Server instance
        - Collects the Password Policy configuration for vCenter Server

        .EXAMPLE
        Request-VcenterPasswordPolicy -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return the Password Policy configuration for vCenter Server managed by SDDC Manager for a workload domain.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $domain }) {
                    if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain)) {
                        if (Test-vSphereApiConnection -server $($vcfVcenterDetails.fqdn)) {
                            if (Test-vSphereApiAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                                Request-vSphereApiToken -fqdn $vcfVcenterDetails.fqdn -username $vcfVcenterDetails.ssoAdmin -password $vcfVcenterDetails.ssoAdminPass | Out-Null
                                $passwordPolicy = Get-VCPasswordPolicy
                                $customObject = New-Object -TypeName psobject
                                $customObject | Add-Member -notepropertyname "vCenter Server FQDN" -notepropertyvalue $vcfVcenterDetails.fqdn
                                $customObject | Add-Member -notepropertyname "Lifetime (max days)" -notepropertyvalue $passwordPolicy.max_days
                                $customObject | Add-Member -notepropertyname "Lifetime (min days)" -notepropertyvalue $passwordPolicy.min_days
                                $customObject | Add-Member -notepropertyname "Warning (days)" -notepropertyvalue $passwordPolicy.warn_days
                            }
                            $customObject | Sort-Object 'vCenter Server FQDN'
                        }
                    }
                    
                } else {
                    Write-Error "Unable to find Workload Domain named ($domain) in the inventory of SDDC Manager ($server): PRE_VALIDATION_FAILED"
                }
            }
        }
    }
	Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Request-VcenterPasswordPolicy

Function Request-SsoPasswordPolicy {
    <#
        .SYNOPSIS
        Returns vCenter Single Sign-On Password Policy.

        .DESCRIPTION
        The Request-SsoPasswordPolicy cmdlet returns the Password Policy for vCenter Single Sign-On managed by
        SDDC Manager. The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Single Sign-On instance
        - Collects the Password Policy configuration forvCenter Server

        .EXAMPLE
        Request-SsoPasswordPolicy -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return the Password Policy configuration for vCenter Single Sign-On managed by SDDC Manager for a workload domain.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $domain }) {
                    if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain)) {
                        if (Test-SsoConnection -server $($vcfVcenterDetails.fqdn)) {
                            if (Test-SsoAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                                $passwordPolicy = Get-SSOPasswordPolicy
                                $customObject = New-Object -TypeName psobject
                                $customObject | Add-Member -notepropertyname "Single Sign-On FQDN" -notepropertyvalue $vcfVcenterDetails.fqdn
                                $customObject | Add-Member -notepropertyname "History" -notepropertyvalue $passwordPolicy.ProhibitedPreviousPasswordsCount
                                $customObject | Add-Member -notepropertyname "Length (min)" -notepropertyvalue $passwordPolicy.MinLength
                                $customObject | Add-Member -notepropertyname "Length (max)" -notepropertyvalue $passwordPolicy.MaxLength
                                $customObject | Add-Member -notepropertyname "Lifetime (days)" -notepropertyvalue $passwordPolicy.PasswordLifetimeDays
                                $customObject | Add-Member -notepropertyname "Numerical (min)" -notepropertyvalue $passwordPolicy.MinNumericCount
                                $customObject | Add-Member -notepropertyname "Special Char (min)" -notepropertyvalue $passwordPolicy.MinSpecialCharCount
                                $customObject | Add-Member -notepropertyname "Identical Adjacent Char (max)" -notepropertyvalue $passwordPolicy.MaxIdenticalAdjacentCharacters
                                $customObject | Add-Member -notepropertyname "Alphabetic Char (min)" -notepropertyvalue $passwordPolicy.MinAlphabeticCount
                                $customObject | Add-Member -notepropertyname "Uppercase Char (min)" -notepropertyvalue $passwordPolicy.MinUppercaseCount
                                $customObject | Add-Member -notepropertyname "Lowercase Char (min)" -notepropertyvalue $passwordPolicy.MinLowercaseCount
                                $customObject | Sort-Object 'Single Sign-On FQDN'
                            }
                        }
                    }
                    Disconnect-SsoAdminServer -Server $vcfVcenterDetails.fqdn
                } else {
                    Write-Error "Unable to find Workload Domain named ($domain) in the inventory of SDDC Manager ($server): PRE_VALIDATION_FAILED"
                }
            }
        }
    }
	Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Request-SsoPasswordPolicy

Function Request-SsoLockoutPolicy {
    <#
        .SYNOPSIS
        Returns vCenter Single Sign-On Lockout Policy.

        .DESCRIPTION
        The Request-SsoLockoutPolicy cmdlet returns the Lockout Policy for vCenter Single Sign-On managed by
        SDDC Manager. The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Single Sign-On instance
        - Collects the Lockout Policy configuration forvCenter Server

        .EXAMPLE
        Request-SsoLockoutPolicy -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return the Lockout Policy configuration for vCenter Single Sign-On managed by SDDC Manager for a workload domain.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $domain }) {
                    if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain)) {
                        if (Test-SsoConnection -server $($vcfVcenterDetails.fqdn)) {
                            if (Test-SsoAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                                $lockoutPolicy = Get-SSOLockoutPolicy
                                $customObject = New-Object -TypeName psobject
                                $customObject | Add-Member -notepropertyname "Single Sign-On FQDN" -notepropertyvalue $vcfVcenterDetails.fqdn
                                $customObject | Add-Member -notepropertyname "Login Attempts" -notepropertyvalue $lockoutPolicy.MaxFailedAttempts
                                $customObject | Add-Member -notepropertyname "Unlock Time (sec)" -notepropertyvalue $lockoutPolicy.AutoUnlockIntervalSec
                                $customObject | Add-Member -notepropertyname "Failed Attempt Inteval (sec)" -notepropertyvalue $lockoutPolicy.FailedAttemptIntervalSec
                                $customObject | Sort-Object 'Single Sign-On FQDN'
                            }
                        }
                    }
                    Disconnect-SsoAdminServer -Server $vcfVcenterDetails.fqdn
                } else {
                    Write-Error "Unable to find Workload Domain named ($domain) in the inventory of SDDC Manager ($server): PRE_VALIDATION_FAILED"
                }
            }
        }
    }
	Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Request-SsoLockoutPolicy

Function Publish-NsxtPolicy {
    <#
        .SYNOPSIS
        Publish password policy for NSX-T Data Center instance managed by SDDC Manager.

        .DESCRIPTION
        The Publish-NsxtPolicy cmdlet returns password policy from NSX-T Data Center by SDDC Manager.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the NSX Manager instance
        - Validates the authentication to NSX Manager with credentials from SDDC Manager
        - Collects password policy from all ESXi hosts in vCenter Server instance

        .EXAMPLE
        Publish-NsxtPolicy -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will return password policy from NSX Manager managed by SDDC Manager for a all workload domains.

        .EXAMPLE
        Publish-NsxtPolicy -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will return password policy from NSX Manager managed by SDDC Manager for a workload domain names sfo-w01.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain
    )
    
    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $allNsxtPolicyObject = New-Object System.Collections.ArrayList
                $allNsxtManagerPasswordPolicyObject = New-Object System.Collections.ArrayList
                $allNsxtEdgePassordPolicyObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('allDomains')) {
                    $allWorkloadDomains = Get-VCFWorkloadDomain
                    foreach ($domain in $allWorkloadDomains ) {
                        $nsxtManagerPasswordPolicy = Request-NsxtManagerPasswordPolicy -server $server -user $user -pass $pass -domain $domain.name; $allNsxtManagerPasswordPolicyObject += $nsxtManagerPasswordPolicy
                        $nsxtEdgePasswordPolicy = Request-NsxtEdgePasswordPolicy -server $server -user $user -pass $pass -domain $domain.name; $allNsxtEdgePassordPolicyObject += $nsxtEdgePasswordPolicy
                    }
                }
                else {
                    $nsxtManagerPasswordPolicy = Request-NsxtManagerPasswordPolicy -server $server -user $user -pass $pass -domain $workloadDomain; $allNsxtManagerPasswordPolicyObject += $nsxtManagerPasswordPolicy
                    $nsxtEdgePasswordPolicy = Request-NsxtEdgePasswordPolicy -server $server -user $user -pass $pass -domain $workloadDomain; $allNsxtEdgePassordPolicyObject += $nsxtEdgePasswordPolicy
                }
                $allNsxtManagerPasswordPolicyObject = $allNsxtManagerPasswordPolicyObject | Sort-Object Cluster, 'NSX Manager FQDN' | ConvertTo-Html -Fragment -PreContent '<a id="policy-password-manager"></a><h3>NSX Manager Password Policy</h3>' -As Table
                $allNsxtManagerPasswordPolicyObject = Convert-CssClass -htmldata $allNsxtManagerPasswordPolicyObject
                $allNsxtEdgePassordPolicyObject = $allNsxtEdgePassordPolicyObject | Sort-Object Cluster, 'NSX Edge' | ConvertTo-Html -Fragment -PreContent '<a id="policy-password-edge"></a><h3>NSX Edge Password Policy</h3>' -As Table
                $allNsxtEdgePassordPolicyObject = Convert-CssClass -htmldata $allNsxtEdgePassordPolicyObject
                $allNsxtPolicyObject += $allNsxtManagerPasswordPolicyObject
                $allNsxtPolicyObject += $allNsxtEdgePassordPolicyObject
                $allNsxtPolicyObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-NsxtPolicy

Function Request-NsxtManagerPasswordPolicy {
    <#
        .SYNOPSIS
        Returns NSX Manager Password Policy.

        .DESCRIPTION
        The Request-NsxtManagerPasswordPolicy cmdlet returns the Password Policy for NSX Manager managed by
        SDDC Manager. The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the NSX Manager instance
        - Collects the Password Policy configuration for the NSX Manager

        .EXAMPLE
        Request-NsxtManagerPasswordPolicy -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return the Password Policy configuration for NSX Manager managed by SDDC Manager for a workload domain.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $domain }) {
                    if (($vcfNsxDetails = Get-NsxtServerDetail -fqdn $server -username $user -password $pass -domain $domain -listNodes)) {
                        $allNsxtManagerObject = New-Object System.Collections.ArrayList
                        foreach ($nsxtManagerNode in $vcfNsxDetails.nodes) {
                            if (Test-NSXTConnection -server $nsxtManagerNode.fqdn) {
                                if (Test-NSXTAuthentication -server $nsxtManagerNode.fqdn -user $vcfNsxDetails.adminUser -pass $vcfNsxDetails.adminPass) {
                                    $passwordPolicy = Get-NsxtManagerAuthPolicy -nsxtManagerNode $nsxtManagerNode.fqdn
                                    $customObject = New-Object -TypeName psobject
                                    $customObject | Add-Member -notepropertyname "NSX Manager FQDN" -notepropertyvalue $nsxtManagerNode.fqdn
                                    $customObject | Add-Member -notepropertyname "Length (min)" -notepropertyvalue $passwordPolicy.minimum_password_length
                                    $customObject | Add-Member -notepropertyname "CLI Failures (max)" -notepropertyvalue $passwordPolicy.cli_max_auth_failures
                                    $customObject | Add-Member -notepropertyname "CLI Lockout" -notepropertyvalue $passwordPolicy.cli_failed_auth_lockout_period
                                    $customObject | Add-Member -notepropertyname "API Failures (max)" -notepropertyvalue $passwordPolicy.api_max_auth_failures
                                    $customObject | Add-Member -notepropertyname "API Lockout" -notepropertyvalue $passwordPolicy.api_failed_auth_lockout_period
                                    $customObject | Add-Member -notepropertyname "API Reset" -notepropertyvalue $passwordPolicy.api_failed_auth_reset_period
                                    $allNsxtManagerObject += $customObject
                                }
                            }
                        }
                        $allNsxtManagerObject | Sort-Object 'NSX Manager FQDN'
                    }
                } else {
                    Write-Error "Unable to find Workload Domain named ($domain) in the inventory of SDDC Manager ($server): PRE_VALIDATION_FAILED"
                }
            }
        }
    }
	Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Request-NsxtManagerPasswordPolicy

Function Request-NsxtEdgePasswordPolicy {
    <#
        .SYNOPSIS
        Returns NSX Edge Password Policy.

        .DESCRIPTION
        The Request-NsxtEdgePasswordPolicy cmdlet returns the Password Policy for NSX Edge managed by
        SDDC Manager. The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the NSX Manager instance
        - Collects the Password Policy configuration for the NSX Manager

        .EXAMPLE
        Request-NsxtEdgePasswordPolicy -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return the Password Policy configuration for NSX Edge managed by SDDC Manager for a workload domain.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $domain }) {
                    if ($vcfNsxDetails = Get-NsxtServerDetail -fqdn $server -username $user -password $pass -domain $domain -listNodes) {
                        if (Test-NSXTAuthentication -server $vcfNsxDetails.fqdn -user $vcfNsxDetails.adminUser -pass $vcfNsxDetails.adminPass) {
                            $allNsxtEdgeObject = New-Object System.Collections.ArrayList
                            $nsxtEdgeNodes = (Get-NsxtEdgeCluster | Where-Object {$_.member_node_type -eq "EDGE_NODE"})
                            # if (Test-NSXTAuthentication -server $nsxtManagerNode.fqdn -user $vcfNsxDetails.adminUser -pass $vcfNsxDetails.adminPass) {
                            foreach ($nsxtEdgeNode in $nsxtEdgeNodes.members) {
                                $edgePolicy = Get-NsxtEdgeNodeAuthPolicy -nsxtManager $vcfNsxDetails.fqdn -nsxtEdgeNodeID $nsxtEdgeNode.transport_node_id  
                                $customObject = New-Object -TypeName psobject
                                $customObject | Add-Member -notepropertyname "NSX Edge" -notepropertyvalue (Get-NsxtEdgeNode -transportNodeID $nsxtEdgeNode.transport_node_id).display_name
                                $customObject | Add-Member -notepropertyname "Length (min)" -notepropertyvalue $edgePolicy.minimum_password_length
                                $customObject | Add-Member -notepropertyname "CLI Failures (max)" -notepropertyvalue $edgePolicy.cli_max_auth_failures
                                $customObject | Add-Member -notepropertyname "CLI Lockout" -notepropertyvalue $edgePolicy.cli_failed_auth_lockout_period
                                $allNsxtEdgeObject += $customObject
                                    
                            }
                            $allNsxtEdgeObject | Sort-Object 'NSX Edge'
                            # }
                        }
                    }
                } else {
                    Write-Error "Unable to find Workload Domain named ($domain) in the inventory of SDDC Manager ($server): PRE_VALIDATION_FAILED"
                }
            }
        }
    }
	Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Request-NsxtEdgePasswordPolicy

##########################################  E N D   O F   F U N C T I O N S  ##########################################
#######################################################################################################################


#######################################################################################################################
###############################  S Y S T E M   O V E R V I E W   F U N C T I O N S   ##################################

Function Publish-VcfSystemOverview {
    <#
        .SYNOPSIS
        Publish system overview report.

        .DESCRIPTION
        The Publish-VcfSystemOverview cmdlet returns password policy from NSX-T Data Center by SDDC Manager.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the NSX Manager instance
        - Validates the authentication to NSX Manager with credentials from SDDC Manager
        - Collects password policy from all ESXi hosts in vCenter Server instance

        .EXAMPLE
        Publish-VcfSystemOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
        This example will return system overview report for SDDC Manager for a all workload domains.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass
    )
    
    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $allOverviewObject = New-Object System.Collections.ArrayList
                $vcfOverview = Request-VcfOverview -server $server -user $user -pass $pass
                $vcenterOverview = Request-VcenterOverview -server $server -user $user -pass $pass
                $clusterOverview = Request-ClusterOverview -server $server -user $user -pass $pass
                $networkingOverview = Request-NetworkOverview -server $server -user $user -pass $pass
                $vrealizeOverview = Request-VrealizeOverview -server $server -user $user -pass $pass

                $vcfOverview = $vcfOverview | ConvertTo-Html -Fragment -PreContent '<h4>VMware Cloud Foundation Overview</h4>'
                $vcfOverview = Convert-CssClass -htmldata $vcfOverview
                $vcenterOverview = $vcenterOverview | ConvertTo-Html -Fragment -PreContent '<h4>vCenter Server Overview</h4>' -As Table
                $vcenterOverview = Convert-CssClass -htmldata $vcenterOverview
                $clusterOverview = $clusterOverview | ConvertTo-Html -Fragment -PreContent '<h4>vSphere Cluster Overview</h4>'
                $clusterOverview = Convert-CssClass -htmldata $clusterOverview
                $networkingOverview = $networkingOverview | ConvertTo-Html -Fragment -PreContent '<h4>Networking Overview</h4>'
                $networkingOverview = Convert-CssClass -htmldata $networkingOverview
                if ($vrealizeOverview) {
                    $vrealizeOverview = $vrealizeOverview | ConvertTo-Html -Fragment -PreContent '<h4>vRealize Suite Overview</h4>'
                    $vrealizeOverview = Convert-CssClass -htmldata $vrealizeOverview
                } else {
                    $vrealizeOverview = $vrealizeOverview | ConvertTo-Html -Fragment -PreContent '<h4>vRealize Suite Overview</h4>' -PostContent '<p>No vRealize Suite Installed.</p>'
                }

                $allOverviewObject += $vcfOverview
                $allOverviewObject += $vcenterOverview
                $allOverviewObject += $clusterOverview
                $allOverviewObject += $networkingOverview
                $allOverviewObject += $vrealizeOverview
                $allOverviewObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-VcfSystemOverview

Function Request-VcfOverview {
    <#
        .SYNOPSIS
        Returns System Overview.

        .DESCRIPTION
        The Request-VcfOverview cmdlet returns an overview of the SDDC Manager instance.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Collects the overview detail

        .EXAMPLE
        Request-VcfOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
        This example will return an overview of the SDDC Manager instance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                # Gather Hardware OEM
                $harwdareOemObject = New-Object System.Collections.ArrayList
                foreach ($esxiHost in (Get-VCFHost)) {
                    if (-not ($harwdareOemObject -match $esxiHost.hardwareVendor)) {
                        $harwdareOemObject.Add($esxiHost.hardwareVendor)
                    }
                }

                # Gather Hardware Platform
                $harwdareModelObject = New-Object System.Collections.ArrayList
                foreach ($esxiHost in (Get-VCFHost)) {
                    if (-not ($harwdareModelObject -match $esxiHost.hardwareModel)) {
                        $harwdareModelObject.Add($esxiHost.hardwareModel)
                    }
                }

                # Gather CPU Sockets / Cores Platform
                $totalSockets = $null
                foreach ($esxiHost in (Get-VCFHost)) {
                    $totalSockets = $totalSockets + $esxiHost.cpu.cpuCores.Count
                }

                # Gather VCF Architecture
                if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT)) {
                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            $vcfArchitecture = (Get-AdvancedSetting -Name "config.SDDC.Deployed.Flavor" -Entity $vcfVcenterDetails.fqdn -Server $vcfVcenterDetails.fqdn).value
                            Disconnect-VIServer -Server $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                        }
                    }
                }

                $customObject = New-Object -TypeName psobject    
                $customObject | Add-Member -notepropertyname "SDDC Manager UUID" -notepropertyvalue (Get-VCFManager).id
                $customObject | Add-Member -notepropertyname "VCF Version" -notepropertyvalue (Get-VCFManager).version
                $customObject | Add-Member -notepropertyname "Hardware OEM" -notepropertyvalue $harwdareOemObject
                $customObject | Add-Member -notepropertyname "Hardware Platform" -notepropertyvalue $harwdareModelObject
                $customObject | Add-Member -notepropertyname "CPUs Sockets Deployed" -notepropertyvalue $totalSockets
                $customObject | Add-Member -notepropertyname "Hosts Deployed" -notepropertyvalue (Get-VCFHost).Count
                $customObject | Add-Member -notepropertyname "Workload Domains" -notepropertyvalue (Get-VCFWorkloadDomain).Count
                $customObject | Add-Member -notepropertyname "VCF Architecture" -notepropertyvalue $vcfArchitecture
                $customObject
            }
        }
    }
	Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Request-VcfOverview

Function Request-VcenterOverview {
    <#
        .SYNOPSIS
        Returns overview of vSphere.

        .DESCRIPTION
        The Request-VcenterOverview cmdlet returns an overview of the vSphere environment managed by SDDC Manager.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity and authantcation to the SDDC Manager instance
        - Validates that network connectivity and authantcation to the vCenter Server instances
        - Collects the vSphere overview detail

        .EXAMPLE
        Request-VcenterOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
        This example will return an overview of the vSphere environment managed by the SDDC Manager instance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass
    )

    Try {
        if (Test-VCFConnection -server $server -ErrorAction SilentlyContinue -ErrorVariable ErrorMessage) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass -ErrorAction SilentlyContinue -ErrorVariable ErrorMessage) {
                $allWorkloadDomains = Get-VCFWorkloadDomain
                $allVsphereObject = New-Object System.Collections.ArrayList
                foreach ($domain in $allWorkloadDomains) {
                    if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain.name)) {
                        if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                            if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                                $customObject = New-Object -TypeName psobject
                                $customObject | Add-Member -notepropertyname "vCenter Server UUID" -notepropertyvalue $domain.vcenters.id
                                $customObject | Add-Member -notepropertyname "vCenter Server Version" -notepropertyvalue (Get-VCFvCenter -id $domain.vcenters.id).version
                                $customObject | Add-Member -notepropertyname "Domain UUID" -notepropertyvalue $domain.id
                                $customObject | Add-Member -notepropertyname "Domain Type" -notepropertyvalue $domain.type.ToLower()
                                $customObject | Add-Member -notepropertyname "Total Clusters" -notepropertyvalue (Get-Cluster -Server $vcfVcenterDetails.fqdn).Count
                                $customObject | Add-Member -notepropertyname "Total Hosts" -notepropertyvalue (Get-VMHost -Server $vcfVcenterDetails.fqdn).Count
                                $customObject | Add-Member -notepropertyname "Total VM Count" -notepropertyvalue (Get-VM -Server $vcfVcenterDetails.fqdn).Count
                                Disconnect-VIServer -Server $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                            }
                        }
                    }
                    $allVsphereObject += $customObject
                }
                $allVsphereObject | Sort-Object 'Domain Type'
            } else {
                Write-LogMessage -Type ERROR -Message "$ErrorMessage"
            }
        } else {
            Write-LogMessage -Type ERROR -Message "$ErrorMessage"
        }
    }
	Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Request-VcenterOverview

Function Request-ClusterOverview {
    <#
        .SYNOPSIS
        Returns overview of vSphere.

        .DESCRIPTION
        The Request-ClusterOverview cmdlet returns an overview of the vSphere environment managed by SDDC Manager.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity and authantcation to the SDDC Manager instance
        - Validates that network connectivity and authantcation to the vCenter Server instances
        - Collects the vSphere overview detail

        .EXAMPLE
        Request-ClusterOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
        This example will return an overview of the vSphere environment managed by the SDDC Manager instance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $allWorkloadDomains = Get-VCFWorkloadDomain
                $allClusterObject = New-Object System.Collections.ArrayList
                foreach ($domain in $allWorkloadDomains) {
                    foreach ($cluster in $domain.clusters) {
                        $customObject = New-Object -TypeName psobject
                        $customObject | Add-Member -notepropertyname "Domain UUID" -notepropertyvalue $domain.id
                        $customObject | Add-Member -notepropertyname "Cluster UUID" -notepropertyvalue $cluster.id
                        $customObject | Add-Member -notepropertyname "Principal Storage" -notepropertyvalue  (Get-VCFCluster -id $cluster.id).primaryDatastoreType
                        $customObject | Add-Member -notepropertyname "Stretched Cluster" -notepropertyvalue  (Get-VCFCluster -id $cluster.id).isStretched
                    }
                    $allClusterObject += $customObject
                }
                $allClusterObject
            }
        }
    }
	Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Request-ClusterOverview

Function Request-NetworkOverview {
    <#
        .SYNOPSIS
        Returns overview of networking.

        .DESCRIPTION
        The Request-NetworkOverview cmdlet returns an overview of the networking managed by SDDC Manager.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity and authantcation to the SDDC Manager instance
        - Collects the networking overview detail

        .EXAMPLE
        Request-NetworkOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
        This example will return an overview of the networking managed by the SDDC Manager instance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $allWorkloadDomains = Get-VCFWorkloadDomain
                $allNetworkingObject = New-Object System.Collections.ArrayList
                foreach ($domain in $allWorkloadDomains) {
                    foreach ($cluster in $domain.clusters) {
                        if (Get-VCFEdgeCluster | Where-Object {$_.nsxtCluster.id -eq $domain.nsxtCluster.id}) { $edgeCluster = "True" } else { $edgeCluster = "False" }
                        if ($domain.type -eq "MANAGEMENT" -and (Get-VCFApplicationVirtualNetwork)) { $avnStatus = "True"} else { $avnStatus = "False" }
                        $customObject = New-Object -TypeName psobject
                        $customObject | Add-Member -notepropertyname "NSX Manager UUID" -notepropertyvalue $domain.nsxtCluster.id
                        $customObject | Add-Member -notepropertyname "NSX Manager Version" -notepropertyvalue (Get-VCFNsxtCluster -id $domain.nsxtCluster.id).version
                        $customObject | Add-Member -notepropertyname "NSX Stretched" -notepropertyvalue (Get-VCFNsxtCluster -id $domain.nsxtCluster.id).isShared
                        $customObject | Add-Member -notepropertyname "Domain UUID" -notepropertyvalue $domain.id
                        $customObject | Add-Member -notepropertyname "Domain Type" -notepropertyvalue $domain.type.ToLower()
                        $customObject | Add-Member -notepropertyname "Edge Cluster" -notepropertyvalue $edgeCluster
                        $customObject | Add-Member -notepropertyname "AVN" -notepropertyvalue $avnStatus
                    }
                    $allNetworkingObject += $customObject 
                }
                $allNetworkingObject | Sort-Object 'Domain Type'
            }
        }
    }
	Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Request-NetworkOverview

Function Request-VrealizeOverview {
    <#
        .SYNOPSIS
        Returns overview of vRealize Suite.

        .DESCRIPTION
        The Request-VrealizeOverview cmdlet returns an overview of vRealize Suite managed by SDDC Manager.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity and authantcation to the SDDC Manager instance
        - Collects the networking overview detail

        .EXAMPLE
        Request-VrealizeOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
        This example will return an overview of vRealize Suite managed by the SDDC Manager instance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $allVrealizeObject = New-Object System.Collections.ArrayList
                $vcfApiCmdlet = @("Get-VCFvRSLCM","Get-VCFWSA","Get-VCFvRLI","Get-VCFvROPS","Get-VCFvRA")
                foreach ($apiCmdlet in $vcfApiCmdlet) {
                    if ((Invoke-Expression $apiCmdlet).status -eq "ACTIVE") {
                        if ($apiCmdlet -eq "Get-VCFvRSLCM") {$nodeCount = "1" } else { ($nodeCount = ((Invoke-Expression $apiCmdlet).nodes).Count)}
                        $customObject = New-Object -TypeName psobject
                        $customObject | Add-Member -notepropertyname "vRealize Product" -notepropertyvalue ((Get-Help -Name $apiCmdlet).synopsis -Split ("Get the existing ") | Select-Object -Last 1)
                        $customObject | Add-Member -notepropertyname "UUID" -notepropertyvalue (Invoke-Expression $apiCmdlet).id
                        $customObject | Add-Member -notepropertyname "Version" -notepropertyvalue (Invoke-Expression $apiCmdlet).version
                        $customObject | Add-Member -notepropertyname "Status" -notepropertyvalue (Invoke-Expression $apiCmdlet).status
                        $customObject | Add-Member -notepropertyname "Nodes" -notepropertyvalue $nodeCount
                        $allVrealizeObject += $customObject
                    }
                }
                $allVrealizeObject
            }
        }
    }
	Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Request-VrealizeOverview

##########################################  E N D   O F   F U N C T I O N S  ##########################################
#######################################################################################################################


#########################################################################################
#############################  Start Supporting Functions  ##############################

Function Test-VcfHealthPrereq {
    <#
		.SYNOPSIS
        Validate prerequisites to run the PowerShell module.

        .DESCRIPTION
        The Test-VcfHealthPrereq cmdlet checks that all the prerequisites have been met to run the PowerShell module.

        .EXAMPLE
        Test-VcfHealthPrereq
        This example runs the prerequisite validation.
    #>

    Try {
        $modules = @( 
            @{ Name=("PowerVCF"); Version=("2.1.7")}
            @{ Name=("PowerValidatedSolutions"); Version=("1.6.0")}
            @{ Name=("VMware.PowerCLI"); Version=("12.4.1")}
            @{ Name=("VMware.vSphere.SsoAdmin"); Version=("1.3.7")}
        )
        foreach ($module in $modules ) {
            if ((Get-InstalledModule -Name $module.Name).Version -lt $module.Version) {
                $message = "PowerShell Module: $($module.Name) Version: $($module.Version) Not Installed, Please update before proceeding"
                $message
                Break
            }
            
        }
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}
Export-ModuleMember -Function Test-VcfHealthPrereq

Function Start-CreateReportDirectory {
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$path,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerFqdn,
        [Parameter (Mandatory = $true)] [ValidateSet("health","alert","config","upgrade","policy","overview")] [String]$reportType
    )

    $filetimeStamp = Get-Date -Format "MM-dd-yyyy_hh_mm_ss"
    if ($reportType -eq "health") { $Global:reportFolder = $path + '\HealthReports\' }
    if ($reportType -eq "alert") { $Global:reportFolder = $path + '\AlertReports\' }
    if ($reportType -eq "config") { $Global:reportFolder = $path + '\ConfigReports\' }
    if ($reportType -eq "upgrade") { $Global:reportFolder = $path + '\UpgradeReports\' }
    if ($reportType -eq "policy") { $Global:reportFolder = $path + '\PolicyReports\' }
    if ($reportType -eq "overview") { $Global:reportFolder = $path + '\OverviewReports\' }
    if (!(Test-Path -Path $reportFolder)) {
        New-Item -Path $reportFolder -ItemType "directory" | Out-Null
    }
    if (Get-Module -ListAvailable VMware.CloudFoundation.Reporting) {
        $source = (((Get-Module -ListAvailable VMware.CloudFoundation.Reporting | Sort-Object Version).path) | Select-Object -Last 1) -Split ('VMware.CloudFoundation.Reporting.psd1').Trim() | Where-Object { $_ -ne "" }
        Copy-Item -Path ("$source*.css") -Destination $path -Force -Confirm:$False
        Copy-Item -Path ("$source*.svg") -Destination $path -Force -Confirm:$False
    } else {
        Copy-Item -Path "./*.css" -Destination $path -Force -Confirm:$False
        Copy-Item -Path "./*.svg" -Destination $path -Force -Confirm:$False
    }
    $Global:reportName = $reportFolder + $sddcManagerFqdn.Split(".")[0] + "-" + $reportType + "-" + $filetimeStamp + ".htm"
}
Export-ModuleMember -Function Start-CreateReportDirectory

Function Invoke-SddcCommand {
    <#
		.SYNOPSIS
        Run a command on SDDC Manager.

        .DESCRIPTION
        The Invoke-SddcCommand cmdlet runs a command within the SDDC Manager appliance. The cmdlet connects to SDDC
        Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the Management Domain vCenter Server instance
        - Runs the command provided within the SDDC Manager appliance

        .EXAMPLE
        Invoke-SddcCommand -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -rootPass VMw@re1! -command "chage -l backup"
        This example runs the command provided on the SDDC Manager appliance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$rootPass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$command
    )

    if (Test-VCFConnection -server $server) {
        if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT)) {
                if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                    if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                        $output = Invoke-VMScript -VM ($server.Split(".")[0]) -ScriptText $command -GuestUser root -GuestPassword $rootPass -Server $vcfVcenterDetails.fqdn
                        $output
                    }
                    Disconnect-VIServer -Server $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                }
            }
        }
    }
}
Export-ModuleMember -Function Invoke-SddcCommand

Function Read-JsonElement {
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [PSCustomObject]$inputData,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    $outputData = New-Object System.Collections.ArrayList
    foreach ($element in $inputData.PsObject.Properties.Value) {
        $elementObject = New-Object -TypeName psobject
        $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue ($element.area -Split (":"))[0].Trim()
        $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
        $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
        $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
        if ($PsBoundParameters.ContainsKey("failureOnly")) {
            if (($element.status -eq "FAILED")) {
                $outputData += $elementObject
            }
        }
        else {
            $outputData += $elementObject
        }
    }
    $outputData
}
Export-ModuleMember -Function Read-JsonElement

Function Convert-TextToHtml {
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sourceFile,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$label
    )

    Get-Content $sourceFile | ConvertTo-HTML -Property @{Label=$label;Expression={$_}} -Fragment
}
Export-ModuleMember -Function Convert-TextToHtml

Function Get-ClarityReportHeader {
    Param (
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$dark
    )

    if ($PsBoundParameters.ContainsKey("dark")) { 
        $styleSheet = "clr-ui-dark.css"
    } else {
        $styleSheet = "clr-ui.css"
    }
    # Define the default Clarity Cascading Style Sheets (CSS) for the HTML report Header
    $clarityCssHeader = '
        <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
        <html xmlns="http://www.w3.org/1999/xhtml">
        
        <head>
            <link href="../'+$styleSheet+'" rel="stylesheet" />
            <style>
                .alertOK {
                    color: #78BE20;
                    font-weight: bold
                }
        
                .alertWarning {
                    color: #EC7700;
                    font-weight: bold
                }
        
                .alertCritical {
                    color: #9F2842;
                    font-weight: bold
                }
                .table th,
                .table td {
                text-align: left;
                }
            </style>
        </head>
        
        <body>
            <div class="main-container">
                <header class="header header-6">
                    <div class="branding">
                        <a href="">
                            <cds-icon shape="vm-bug">
                                <img src="../icon.svg" alt="VMware Cloud Foundation"/>
                            </cds-icon>
                            <span class="title">VMware Cloud Foundation</span>
                        </a>
                    </div>
                </header>'
    $clarityCssHeader
}
Export-ModuleMember -Function Get-ClarityReportHeader

Function Get-ClarityReportNavigation {
    Param (
        [Parameter (Mandatory = $true)] [ValidateSet("health","alert","config","upgrade","policy","overview")] [String]$reportType
    )

    if ($reportType -eq "health") { # Define the Clarity Cascading Style Sheets (CSS) for a Health Report
        $clarityCssNavigation = '
                <nav class="subnav">
                <ul class="nav">
                <li class="nav-item">
                    <a class="nav-link active" href="">Health Report</a>
                </li>
                </ul>
            </nav>
            <div class="content-container">
            <nav class="sidenav">
            <section class="sidenav-content">
                <section class="nav-group collapsible">
                    <input id="general" type="checkbox"/>
                    <label for="general">General</label>
                    <ul class="nav-list">
                        <li><a class="nav-link" href="#general-service">Service Health</a></li>
                        <li><a class="nav-link" href="#general-connectivity">Connectivity</a></li>
                    </ul>
                </section>
                <section class="nav-group collapsible">
                    <input id="security" type="checkbox"/>
                    <label for="security">Security</label>
                    <ul class="nav-list">
                        <li><a class="nav-link" href="#security-password">Passwords</a></li>
                        <li><a class="nav-link" href="#security-certificate">Certificates</a></li>
                    </ul>
                </section>
                <section class="nav-group collapsible">
                <input id="infrastructure" type="checkbox"/>
                <label for="infrastructure">Infrastructure</label>
                <ul class="nav-list">
                    <li><a class="nav-link" href="#infra-backup">Backups</a></li>
                    <li><a class="nav-link" href="#infra-snapshot">Snapshots</a></li>
                    <li><a class="nav-link" href="#infra-dns-forward">DNS Forward Lookup</a></li>
                    <li><a class="nav-link" href="#infra-dns-reverse">DNS Reverse Lookup</a></li>
                    <li><a class="nav-link" href="#infra-ntp">Network Time</a></li>
                </ul>
                </section>
                <section class="nav-group collapsible">
                    <input id="vcenter" type="checkbox"/>
                    <label for="vcenter">vCenter Server</label>
                    <ul class="nav-list">
                        <li><a class="nav-link" href="#vcenter-overall">Overall Health</a></li>
                        <li><a class="nav-link" href="#vcenter-ring">Single Sign-On Health</a></li>
                    </ul>
                </section>
                <section class="nav-group collapsible">
                    <input id="esxi" type="checkbox"/>
                    <label for="esxi">ESXi</label>
                    <ul class="nav-list">
                        <li><a class="nav-link" href="#esxi-overall">Overall Health</a></li>
                        <li><a class="nav-link" href="#esxi-coredump">Core Dump Health</a></li>
                        <li><a class="nav-link" href="#esxi-disk">Disk Health</a></li>
                        <li><a class="nav-link" href="#esxi-license">Licensing Health</a></li>
                    </ul>
                </section>
                <section class="nav-group collapsible">
                    <input id="vsan" type="checkbox"/>
                    <label for="vsan">vSAN</label>
                    <ul class="nav-list">
                        <li><a class="nav-link" href="#vsan-overall">Overall Health</a></li>
                        <li><a class="nav-link" href="#vsan-spbm">Storage Policy Health</a></li>
                    </ul>
                </section>
                <section class="nav-group collapsible">
                    <input id="nsx" type="checkbox"/>
                    <label for="nsx">NSX-T Data Center</label>
                    <ul class="nav-list">
                        <li><a class="nav-link" href="#nsx-local-manager">NSX Managers (Local)</a></li>
                        <li><a class="nav-link" href="#nsx-edge-cluster">NSX Edge Cluster</a></li>
                        <li><a class="nav-link" href="#nsx-edge">NSX Edge Nodes</a></li>
                        <li><a class="nav-link" href="#nsx-tn">NSX Transport Nodes</a></li>
                        <li><a class="nav-link" href="#nsx-t0-bgp">NSX Tier-0 Gateway BGP</a></li>
                    </ul>
                </section>
                <section class="nav-group collapsible">
                    <input id="storage" type="checkbox"/>
                    <label for="storage">Storage</label>
                    <ul class="nav-list">
                        <li><a class="nav-link" href="#storage-sddcmanager">SDDC Manager</a></li>
                        <li><a class="nav-link" href="#storage-vcenter">vCenter Server</a></li>
                        <li><a class="nav-link" href="#storage-esxi">ESXi</a></li>
                        <li><a class="nav-link" href="#storage-datastore">Datastores</a></li>
                    </ul>
                </section>
            </section>
            </nav>
                <div class="content-area">
                    <div class="content-area">'
        $clarityCssNavigation
    }

    if ($reportType -eq "alert") { # Define the Clarity Cascading Style Sheets (CSS) for a System Alert Report
        $clarityCssNavigation = '
                <nav class="subnav">
                <ul class="nav">
                <li class="nav-item">
                    <a class="nav-link active" href="">Alert Report</a>
                </li>
                </ul>
            </nav>
            <div class="content-container">
            <nav class="sidenav">
            <section class="sidenav-content">
                <a class="nav-link nav-icon" href="#alert-vcenter">vCenter Server</a>
                <a class="nav-link nav-icon" href="#alert-esxi">ESXi</a>
                <a class="nav-link nav-icon" href="#alert-vsan">vSAN</a>
                <a class="nav-link nav-icon" href="#alert-nsx">NSX-T Data Center</a>
            </section>
            </nav>
                <div class="content-area">
                    <div class="content-area">'
        $clarityCssNavigation
    }

    if ($reportType -eq "config") { # Define the Clarity Cascading Style Sheets (CSS) for a Configuration Report
        $clarityCssNavigation = '
                <nav class="subnav">
                <ul class="nav">
                <li class="nav-item">
                    <a class="nav-link active" href="">Configuration Report</a>
                </li>
                </ul>
            </nav>
            <div class="content-container">
            <nav class="sidenav">
            <section class="sidenav-content">
                <a class="nav-link nav-icon" href="#config-vcenter">vCenter Server</a>
                <a class="nav-link nav-icon" href="#config-vsan">vSAN</a>
                <section class="nav-group collapsible">
                    <input id="esxi" type="checkbox"/>
                    <label for="esxi">ESXi</label>
                    <ul class="nav-list">
                        <li><a class="nav-link" href="#esxi-coredump">ESXi Core Dump</a></li>
                    </ul>
                </section>
                <a class="nav-link nav-icon" href="#config-nsx">NSX Manager</a>
            </section>
            </nav>
                <div class="content-area">
                    <div class="content-area">'
        $clarityCssNavigation
    }

    if ($reportType -eq "upgrade") { # Define the Clarity Cascading Style Sheets (CSS) for a Upgrade Report
        $clarityCssNavigation = '
            <nav class="subnav">
            <ul class="nav">
                <li class="nav-item">
                <a class="nav-link active" href="">Upgrade Precheck Report</a>
                </li>
            </ul>
            </nav>
            <div class="content-container">
            <div class="content-area">'
        $clarityCssNavigation
    }

    if ($reportType -eq "policy") { # Define the Clarity Cascading Style Sheets (CSS) for a Password Policy Report
        $clarityCssNavigation = '
                <nav class="subnav">
                <ul class="nav">
                <li class="nav-item">
                    <a class="nav-link active" href="">Password Policy Report</a>
                </li>
                </ul>
            </nav>
            <div class="content-container">
            <nav class="sidenav">
            <section class="sidenav-content">
                <section class="nav-group collapsible">
                    <input id="vcenter" type="checkbox"/>
                    <label for="vcenter">vCenter Server</label>
                    <ul class="nav-list">
                        <li><a class="nav-link" href="#policy-password-vcenter-root">Password Policy (root)</a></li>
                        <li><a class="nav-link" href="#policy-password-vcenter">Password Policy</a></li>
                        <li><a class="nav-link" href="#policy-password-sso">SSO Password Policy</a></li>
                        <li><a class="nav-link" href="#policy-lockout-sso">SSO Lockout Policy</a></li>
                    </ul>
                </section>
                <section class="nav-group collapsible">
                    <input id="esxi" type="checkbox"/>
                    <label for="esxi">ESXi Server</label>
                    <ul class="nav-list">
                        <li><a class="nav-link" href="#policy-password-esxi">Password Policy</a></li>
                        <li><a class="nav-link" href="#policy-lockout-esxi">Lockout Policy</a></li>
                    </ul>
                </section>
                <section class="nav-group collapsible">
                <input id="nsx" type="checkbox"/>
                <label for="ns">NSX-T Data Center</label>
                <ul class="nav-list">
                    <li><a class="nav-link" href="#policy-password-manager">Manager Password Policy</a></li>
                    <li><a class="nav-link" href="#policy-password-edge">Edge Password Policy</a></li>
                </ul>
            </section>
            </section>
            </nav>
                <div class="content-area">
                    <div class="content-area">'
        $clarityCssNavigation
    }

    if ($reportType -eq "overview") { # Define the Clarity Cascading Style Sheets (CSS) for a System Overview Report
        $clarityCssNavigation = '
            <nav class="subnav">
            <ul class="nav">
                <li class="nav-item">
                <a class="nav-link active" href="">System Overview Report</a>
                </li>
            </ul>
            </nav>
            <div class="content-container">
            <div class="content-area">'
        $clarityCssNavigation
    }
}
Export-ModuleMember -Function Get-ClarityReportNavigation

Function Get-ClarityReportFooter {
    # Define the default Clarity Cascading Style Sheets (CSS) for the HTML report Footer
    $clarityCssFooter = '
                </div>
            </div>
        </div>
    </body>
    </html>'
    $clarityCssFooter
}
Export-ModuleMember -Function Get-ClarityReportFooter

Function Format-DfStorageHealth {
    <#
		.SYNOPSIS
        Formats output from 'fd -h' command and sets alerts based on thresholds.

        .DESCRIPTION
        The Format-DfStorageHealth cmdlet formats and returns output from 'df -h' in html or plain text

        .EXAMPLE
        Format-DfStorageHealth -reportTitle '<h3>SDDC Manager Disk Health Status</h3>' -dfOutput $dfOutput -html -failureOnly -greenThreshold 20 -redThreshold 40
        This example returns only failures (Alert is not GREEN), produces html report with title '<h3>SDDC Manager Disk Health Status</h3>' and overwrites the default thresholds
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] $dfOutput,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] $systemFqdn,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly,
        [Parameter (Mandatory = $false)] [ValidateRange(1, 100)] [int]$greenThreshold = 70, # Define default value for "Green" threshold
        [Parameter (Mandatory = $false)] [ValidateRange(1, 100)] [int]$redThreshold = 85   # Define default value for "Red" threshold
    )

    Try {
        # Define object that will be returned and format input
        $customObject = New-Object System.Collections.ArrayList
        $formatOutput = ($dfOutput -split '\r?\n').Trim() -replace '(^\s+|\s+$)', '' -replace '\s+', ' '

        # Set Alarms for each partition
        foreach ($partition in $formatOutput) {
            $usage = $partition.Split(" ")[4]
            # Make sure that only rows with calculated usage will be included
            if ( !$usage ) { continue }

            # Get the usage percentage as numeric value
            $usage = $usage.Substring(0, $usage.Length - 1)
            $usage = [int]$usage

            # Applying thresholds and creating collection from input
            Switch ($usage) {
                { $_ -le $greenThreshold } {
                    $alert = 'GREEN' # Green if $usage is up to $greenThreshold
                    $message = "Used space is less than $greenThreshold%."
                }
                { $_ -ge $redThreshold } {
                    $alert = 'RED' # Red if $usage is equal or above $redThreshold
                    $message = "Used space is above $redThreshold%. Please reclaim space on the partition."
                    # TODO: Find how to display the message in html on multiple rows (Add <br> with the right escape chars)
                    # In order to display usage, you could run as root in SDDC Manager 'du -Sh <mount-point> | sort -rh | head -10' "
                    # As an alternative you could run PowerCLI commandlet:
                    # 'Invoke-SddcCommand -server <SDDC_Manager_FQDN> -user <administrator@vsphere.local> -pass <administrator@vsphere.local_password> -rootPass <SDDC_Manager_RootPassword> -command "du -Sh <mount-point> | sort -rh | head -10" '
                }
                Default {
                    # TODO: Same as above - add hints on new lines }
                    $alert = 'YELLOW' # Yellow if above two are not matched
                    $message = "Used space is between $greenThreshold% and $redThreshold%. Please consider reclaiming some space on the partition."
                }
            }
            
            # Skip population of object if "failureOnly" is selected and alert is "GREEN"
            if (($PsBoundParameters.ContainsKey("failureOnly")) -and ($alert -eq 'GREEN')) { continue }

            $userObject = New-Object -TypeName psobject
            $userObject | Add-Member -notepropertyname 'FQDN' -notepropertyvalue $systemFqdn
            $userObject | Add-Member -notepropertyname 'Filesystem' -notepropertyvalue $partition.Split(" ")[0]
            $userObject | Add-Member -notepropertyname 'Size' -notepropertyvalue $partition.Split(" ")[1]
            $userObject | Add-Member -notepropertyname 'Available' -notepropertyvalue $partition.Split(" ")[2]
            $userObject | Add-Member -notepropertyname 'Used %' -notepropertyvalue $partition.Split(" ")[4]
            $userObject | Add-Member -notepropertyname 'Mounted on' -notepropertyvalue $partition.Split(" ")[5]
            $userObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $alert
            $userObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $message
            $customObject += $userObject # Creating collection to work with afterwords
        }
        $customObject | Sort-Object FQDN # Return $customObject in HTML or pain format
    }
    Catch {
        Debug-CatchWriter -object $_
    } 
}
Export-ModuleMember -Function Format-DfStorageHealth

Function Convert-CssClass {
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [PSCustomObject]$htmlData
    )

    # Function to replace Alerts with colour coded CSS Style
    $oldAlertOK = '<td>GREEN</td>'
    $newAlertOK = '<td class="alertOK">GREEN</td>'
    $oldAlertCritical = '<td>RED</td>'
    $newAlertCritical = '<td class="alertCritical">RED</td>'
    $oldAlertWarning = '<td>YELLOW</td>'
    $newAlertWarning = '<td class="alertWarning">YELLOW</td>'
    $oldTable = '<table>'
    $newTable = '<table class="table">'

    $htmlData = $htmlData -replace $oldAlertOK,$newAlertOK
    $htmlData = $htmlData -replace $oldAlertCritical,$newAlertCritical
    $htmlData = $htmlData -replace $oldAlertWarning,$newAlertWarning
    $htmlData = $htmlData -replace $oldTable,$newTable
    $htmlData
}
Export-ModuleMember -Function Convert-CssClass

Function Format-StorageThreshold {
    <#
        .SYNOPSIS
        Calculate storage percentage.

        .DESCRIPTION
        The Format-StorageThreshold cmdlet converts the storage to a percentage and checks capacity .

        .EXAMPLE
        Format-StorageThreshold -size <size> -free <free>
        This example returns the status of the BGP routing for NSX Tier-0 gateway.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$size,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$free

    )

    Try {
        # Define thresholds Green < Yellow < Red
        $greenThreshold = 80
        $redThreshold = 90
        # Calculate datastore usage and capacity
        [Int]$usage = [Math]::Round((($size - $free) / $size * 100))
        # Applying thresholds and creating collection from input
        Switch ($usage) {
            { $_ -le $greenThreshold } {
                # Green if $usage is up to $greenThreshold
                $alert = 'GREEN'
                $message = "Used space is less than $greenThreshold%. "
            }
            { $_ -ge $redThreshold } {
                # Red if $usage is equal or above $redThreshold
                $alert = 'RED'
                $message = "Used space is above $redThreshold%. Please reclaim space on the volume."
            }
            Default {
                # Yellow if above two are not matched
                $alert = 'YELLOW'
                $message = "Used space is between $greenThreshold% and $redThreshold%. Please consider reclaiming some space on the volume."
            }
        }
        $thresholdObject = New-Object -TypeName psobject
        $thresholdObject | Add-Member -notepropertyname 'usage' -notepropertyvalue $usage
        $thresholdObject | Add-Member -notepropertyname 'alert' -notepropertyvalue $alert
        $thresholdObject | Add-Member -notepropertyname 'message' -notepropertyvalue $message
        $thresholdObject
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}

Function Request-LocalUserExpiry {
    <#
        .SYNOPSIS
        Check the expiry of a local OS user on the Linux-based appliance.

        .DESCRIPTION
        The Request-LocalUserExpiry cmdlet checks the expiry details of a local OS user on Linux-based appliance and
        outputs the results.

        .EXAMPLE
        Request-LocalUserExpiry -fqdn sfo-vcf01.sfo.rainpole.io -rootPass VMw@re1! -component SDDC -checkUser backup
        This example runs the command to check the expiration status of the local OS user named 'backup'.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$fqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$rootPass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$checkUser,
        [Parameter (Mandatory = $true)] [ValidateSet("SDDC","vCenter","NSX Manager", "NSX Edge", "vRSLCM")] [String]$component
    )

    Try {
        if (Get-VM -Name ($fqdn.Split(".")[0])) {
            $command = 'chage -l ' + $checkUser
            $output = Invoke-VMScript -VM ($fqdn.Split(".")[0]) -ScriptText $command -GuestUser root -GuestPassword $rootPass
            $formatOutput = ($output.ScriptOutput -split '\r?\n').Trim()
            $formatOutput = $formatOutput -replace '(^\s+|\s+$)', '' -replace '\s+', ' '

            # Get the current date and expiration date
            Add-Type  -AssemblyName  Microsoft.VisualBasic
            $endDate = ($formatOutput[1] -Split (':'))[1].Trim()
            if ($endDate -ne "never") {
                $expiryDays = [math]::Ceiling((([DateTime]$endDate) - (Get-Date)).TotalDays)
            }

            # Set the alet for the local user account based on the expiry date
            if ($endDate -eq "never") {
                $alert = 'GREEN'
                $message = "Password set to never expire. Verified using $command."
            } else {
                if ($expiryDays -le 15) {
                    $alert = 'YELLOW'  # Warning: <= 15 days
                    $message = "Password will expire in 15 or less days. Verified using $command."
                }
                if ($expiryDays -le 5) {
                    $alert = 'RED'     # Critical: <= 5 days
                    $message = "Password will expire in less than 5 days or has already expired. Verified using $command."
                } else {
                    $alert = 'GREEN'   # OK: > 15 days
                    $message = "Password will not expire within the next 15 days. Verified using $command."
                }
            }

            $userObject = New-Object -TypeName psobject
            $userObject | Add-Member -notepropertyname 'Component' -notepropertyvalue $component
            $userObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue $fqdn
            $userObject | Add-Member -notepropertyname 'User' -notepropertyvalue $checkUser
            $userObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $alert
            $userObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $message
            $userObject
        } else {
            Write-Error "Unable to locate virtual machine ($($fqdn.Split(".")[0])) in the vCenter Server inventory, check details"
        }

    }
    Catch {
        Write-Error $_.Exception.Message
    }
}
Export-ModuleMember -Function Request-LocalUserExpiry

Function Get-NsxtBackupConfiguration {
    <#
        .SYNOPSIS
        Return the backup configuration for an NSX Manager cluster.

        .DESCRIPTION
        The Get-NsxtBackupConfiguration cmdlet returns the backup configuration for an NSX Manager cluster

        .EXAMPLE
        Get-NsxtBackupConfiguration -fqdn sfo-w01-nsx01.sfo.rainpole.io
        This example returns the backup configuration for the NSX Manager cluster named 'sfo-w01-nsx01.sfo.rainpole.io'.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$fqdn
    )

    Try {
        $uri = "https://$fqdn/api/v1/cluster/backups/config"
        # Note: NSX-T v3.2.0 and later use `/policy/api/v1/cluster/backups/config` or `/api/v1/cluster/backups/config`
        $response = Invoke-RestMethod -Method 'GET' -Uri $uri -Headers $nsxtHeaders
        $response
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}
Export-ModuleMember -Function Get-NsxtBackupConfiguration

Function Get-NsxtBackupHistory {
    <#
        .SYNOPSIS
        Return the backup history for an NSX Manager cluster.

        .DESCRIPTION
        The Get-NsxtBackupHistory cmdlet returns the backup history for an NSX Manager cluster

        .EXAMPLE
        Get-NsxtBackupHistory -fqdn sfo-w01-nsx01.sfo.rainpole.io
        This example returns the backup history for the NSX Manager cluster named 'sfo-w01-nsx01.sfo.rainpole.io'.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$fqdn
    )

    Try {
        $uri = "https://$nsxtManager/api/v1/cluster/backups/history"
        $response = Invoke-RestMethod -Method 'GET' -Uri $uri -Headers $nsxtHeaders
        $response
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}
Export-ModuleMember -Function Get-NsxtBackupHistory

Function Get-VcenterBackupConfiguration {
    <#
        .SYNOPSIS
        Return the backup configuration for a vCenter Server instance.

        .DESCRIPTION
        The Get-VcenterBackupConfiguration cmdlet returns the backup configuration for a vCenter Server instance.

        .EXAMPLE
        Get-VcenterBackupConfiguration
        This example returns the backup configuration for the connected vCenter Server instance.
    #>

    Try {
        $backupScheduleAPI = Get-CisService -name 'com.vmware.appliance.recovery.backup.schedules' # Get the backup job API from the vSphere Automation API
        $backupSchedules = $backupScheduleAPI.list()
        if ($backupSchedules.count -ge 1) {
            $customObject = @()
            foreach ($backupSchedule in $backupSchedules) {
                $customObject += $backupSchedule.values | Select-Object *, @{N = 'ID'; e = { "$($backupSchedule.keys.value)" } } -ExpandProperty recurrence_info -ExcludeProperty Help | Select-Object * -ExcludeProperty recurrence_info, Help | Select-Object * -ExpandProperty retention_info | Select-Object * -ExcludeProperty retention_info, Help
            }
            return $customObject
        } else {
            continue
        }
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}
Export-ModuleMember -Function Get-VcenterBackupConfiguration

Function Get-VcenterBackupJobs {
    <#
        .SYNOPSIS
        Returns a list of all backup jobs performed on a vCenter Server instance.

        .DESCRIPTION
        The Get-VcenterBackupJobs cmdlet returns a list of all performed on a vCenter Server instance.

        .EXAMPLE
        Get-VcenterBackupJobs -fqdn sfo-m01-vc01.sfo.rainpole.io
        This example returns a list of all backup jobs performed on the vCenter Server instance sfo-m01-vc01.sfo.rainpole.io.

        .EXAMPLE
        Get-VcenterBackupJobs -fqdn sfo-m01-vc01.sfo.rainpole.io -latest
        This example returns the latest backup job performed on the vCenter Server instance sfo-m01-vc01.sfo.rainpole.io.

        .EXAMPLE
        Get-VcenterBackupJobs | Select -First 1 | Get-VcenterBackupStatus
        This example demonstrates piping the results of this function into the Get-VcenterBackupStatus function.
    #>

    Param (
        [Parameter(Mandatory = $false)] [switch]$latest
    )
    
    $backupJobAPI = Get-CisService 'com.vmware.appliance.recovery.backup.job' # Get the backup job API from the vSphere Automation API

    Try {
        if ($PsBoundParameters.ContainsKey('latest')) {
            $results = $backupJobAPI.list()
            $results[0] # Return the latest backup job
        } else {
            $backupJobAPI.list() # Return all backup jobs
        }
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}
Export-ModuleMember -Function Get-VcenterBackupJobs

Function Get-VcenterBackupStatus {
    <#
        .SYNOPSIS
        Returns the status of a backup job(s).

        .DESCRIPTION
        The Get-VcenterBackupStatus cmdlet returns the status of a backup job(s).

        .EXAMPLE
        Get-VcenterBackupStatus -jobId "YYYYMMDD-hhmmss-buildnumber"
        This example returns the status of the backup job with the jobId "YYYYMMDD-hhmmss-buildnumber".
    #>

    Param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)][string[]]$jobId
    )

    Try {
        $backupJobAPI = Get-CisService 'com.vmware.appliance.recovery.backup.job' # Get the backup job API from the vSphere Automation API
        foreach ($id in $jobID) {
            $backupJobAPI.get("$id") | Select-Object id, progress, state, start_time, end_time, messages
        }
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}
Export-ModuleMember -Function Get-VcenterBackupStatus

Function Get-SnapshotStatus {
    <#
        .SYNOPSIS
        Returns the status of a virtual machine's snapshots.

        .DESCRIPTION
        The Get-SnapshotStatus cmdlet returns the status of a virtual machine's snapshots.

        .EXAMPLE
        Get-SnapshotStatus -vm "foo"
        This example returns the status of the snapshots for the virtual machine named "foo".
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$vm
    )

    Try {
        $response = Get-VM $vm | Get-Snapshot | Select-Object -Property Name, Created, isCurrent # Get the snapshot details
        $response # Return the snapshot details
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}
Export-ModuleMember -Function Get-SnapshotStatus

Function Get-SnapshotConsolidation {
    <#
        .SYNOPSIS
        Returns the status of a virtual machine's need for snapshot consolidation.

        .DESCRIPTION
        The Get-SnapshotConsolidation cmdlet returns the status of a virtual machine's need for snapshot consolidation.

        .EXAMPLE
        Get-SnapshotConsolidation -vm "foo"
        This example returns the status of the snapshot consolidation for the virtual machine named "foo".
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$vm
    )

    Try {
        $response = (Get-View -ViewType VirtualMachine -Filter @{'Name' = $vm }).Runtime.ConsolidationNeeded # Get the consolidation status
        $response # Return the consolidation status
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}
Export-ModuleMember -Function Get-SnapshotConsolidation

<<<<<<< HEAD
Function Get-EsxiAlert {
    <#
        .SYNOPSIS
        Returns the triggered alarms for an ESXi host.

        .DESCRIPTION
        The Get-EsxiAlert cmdlet returns all triggered alarms for ESXi host.

        .EXAMPLE
        Get-EsxiAlert -host sfo-w01-esx01.sfo.rainpole.io
        This example returns all triggered alarms for and ESXi host named sfo-w01-esx01.sfo.rainpole.io.
    #>

=======
Function Get-VsanHealthTest {
    <# ToDo#>
>>>>>>> 2f66ad5 (Request-VsanAlert)
    Param (
<<<<<<< HEAD
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
<<<<<<< HEAD
=======

>>>>>>> b2bffce (remove connect-viserver from support functions)
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$host
    )
    $vmhosts = Get-VMHost
    $vmhost = $vmhosts | Where-Object {$_.name -eq $host}
    foreach ($triggeredAlarm in $vmhost.ExtensionData.TriggeredAlarmState) {
        $alarm = "" | Select-Object Entity, Alarm, Status, Time, Acknowledged, AckBy, AckTime
        $alarm.Alarm = (Get-AlarmDefinition -id $triggeredAlarm.alarm).name
        $alarm.Entity =  ( $vmhosts | Where-Object {$_.id -eq $triggeredAlarm.Entity} ).name # or just $host
        $alarm.Status = $triggeredAlarm.OverallStatus
        $alarm.Time = $triggeredAlarm.Time
        $alarm.Acknowledged = $triggeredAlarm.Acknowledged
        $alarm.AckBy = $triggeredAlarm.AcknowledgedByUser
        $alarm.AckTime = $triggeredAlarm.AcknowledgedTime
        $alarm
    }
}
Export-ModuleMember -Function Get-EsxiAlert
<<<<<<< HEAD
<<<<<<< HEAD

=======
=======
=======

>>>>>>> 3a76cbf (Remove Posh-SSH for Request-EsxiStorageCapacity)
Function Get-VsanHealthTest {
    <#
        .SYNOPSIS
        Returns the vSAN healthcheck tests from a vSAN cluster in vCenter Server.

        .DESCRIPTION
        The Get-VsanHealthTest cmdlet returns all vSAN healthcheck tests from a VSAN cluster in vCenter Server.

        .EXAMPLE
        Get-VsanHealthTest -cluster sfo-m01-c01
        This example returns all vSAN healthcheck tests from vSAN cluster sfo-m01-c01 in connected vCenter Server.
    #>

    Param (
<<<<<<< HEAD
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
>>>>>>> 5a04e62 (Get-VsanHealthTest)
=======
>>>>>>> b2bffce (remove connect-viserver from support functions)
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$cluster
    )

    $vsanClusterHealthSystem = Get-VSANView -Id "VsanVcClusterHealthSystem-vsan-cluster-health-system"
    $clusterView = (Get-Cluster -Name $cluster).ExtensionData.MoRef
    $results = $vsanClusterHealthSystem.VsanQueryVcClusterHealthSummary($clusterView,$null,$null,$true,$null,$null,'defaultView')
    $healthCheckGroups = $results.groups
    
    $healthTests = New-Object System.Collections.ArrayList
    
    foreach ($healthCheckGroup in $healthCheckGroups) {
        foreach ($test in $healthCheckGroup.GroupTests) {
            $testResult = [pscustomobject] @{
                GroupName = $healthCheckGroup.GroupName
                TestName = $test.TestName
                TestHealth = $test.TestHealth.ToUpper()
            }
            $healthTests += $testResult
        }
    }
    $healthTests 
}
Export-ModuleMember -Function Get-VsanHealthTest
>>>>>>> 2f66ad5 (Request-VsanAlert)
Function Get-VcenterTriggeredAlarm {
    <#
        .SYNOPSIS
        Returns the triggered alarms for a vCenter Server instance.

        .DESCRIPTION
        The Get-VcenterTriggeredAlarm cmdlet returns all triggered alarms from vCenter Server instance.

        .EXAMPLE
        Get-VcenterTriggeredAlarm -server sfo-w01-vc01.sfo.rainpole.io
        This example returns all triggered alarms for a vCenter Server instance named sfo-w01-vc01.sfo.rainpole.io.
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server
    )

    $rootFolder = Get-Folder -Server $server "Datacenters"
    foreach ($triggeredAlarm in $rootFolder.ExtensionData.TriggeredAlarmState) {
        $alarm = "" | Select-Object EntityType, Alarm, Status, Time, Acknowledged, AckBy, AckTime
        $alarm.Alarm = (Get-View -Server $server $triggeredAlarm.Alarm).Info.Name
        $alarm.EntityType = (Get-View -Server $server $triggeredAlarm.Entity).GetType().Name
        $alarm.Status = $triggeredAlarm.OverallStatus
        $alarm.Time = $triggeredAlarm.Time
        $alarm.Acknowledged = $triggeredAlarm.Acknowledged
        $alarm.AckBy = $triggeredAlarm.AcknowledgedByUser
        $alarm.AckTime = $triggeredAlarm.AcknowledgedTime
        $alarm
<<<<<<< HEAD
<<<<<<< HEAD
    }
    Disconnect-VIServer -Server $server -Confirm:$false
=======
  	}
>>>>>>> b2bffce (remove connect-viserver from support functions)
=======
    }
>>>>>>> 020b166 (Adjust Alert Output on Report)
}
Export-ModuleMember -Function Get-VcenterTriggeredAlarm

Function Get-NsxtAlarm {
    <#
        .SYNOPSIS
        Return the triggered alarms for an NSX Manager cluster.

        .DESCRIPTION
        The Get-NsxtAlarm cmdlet returns all triggered alarms for an NSX Manager cluster.

        .EXAMPLE
        Get-NsxtAlarm -fqdn sfo-w01-nsx01.sfo.rainpole.io
        This example returns all triggered alarms for an NSX Manager cluster named sfo-w01-nsx01.sfo.rainpole.io.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$fqdn
    )

    Try {
        $uri = "https://$nsxtManager/api/v1/alarms"
        $response = Invoke-RestMethod -Method 'GET' -Uri $uri -Headers $nsxtHeaders
        $response
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}
Export-ModuleMember -Function Get-NsxtAlarm

Function Get-NsxtEvent {
    <#
        .SYNOPSIS
        Return the events for an NSX Manager cluster.

        .DESCRIPTION
        The Get-NsxtEvent cmdlet returns the events for an NSX Manager cluster.

        .EXAMPLE
        Get-NsxtEvent -fqdn sfo-w01-nsx01.sfo.rainpole.io
        This example returns events for an NSX Manager cluster named sfo-w01-nsx01.sfo.rainpole.io.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$fqdn
    )

    Try {
        $uri = "https://$nsxtManager/api/v1/events"
        $response = Invoke-RestMethod -Method 'GET' -Uri $uri -Headers $nsxtHeaders
        $response
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}
Export-ModuleMember -Function Get-NsxtEvent

Function Get-NsxtTier0BgpStatus {
    <#
        .SYNOPSIS
        Returns the status of the BGP routing for NSX Tier-0 gateways.

        .DESCRIPTION
        The Get-NsxtTier0BgpStatus cmdlet returns the status of the BGP routing for NSX Tier-0 gateways.

        .EXAMPLE
        Get-NsxtTier0BgpStatus -id <guid>
        This example returns the status of the BGP routing for NSX Tier-0 gateway.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$id
    )

    Try {

        $uri = "https://$nsxtManager/policy/api/v1/infra/tier-0s/$id/locale-services/default/bgp/neighbors/status"
        $response = Invoke-RestMethod -Method 'GET' -Uri $uri -Headers $nsxtHeaders
        $response.results
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}
Export-ModuleMember -Function Get-NsxtTier0BgpStatus

Function Get-NsxtEdgeNode {
    <#
        .SYNOPSIS
        Get details for NSX Edge.

        .DESCRIPTION
        The Get-NsxtEdgeNode cmdlet returns the details of an NSX Edge node

        .EXAMPLE
        Get-NsxtEdgeNode -transportNodeId sfo-w01-nsx01.sfo.rainpole.io
        This example returns the details of an NSX Edge node
    #>

	Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$transportNodeId
    )

    Try {
        $uri = "https://$nsxtmanager/api/v1/transport-nodes/$transportNodeId"
        Invoke-RestMethod -Method GET -URI $uri -headers $nsxtHeaders
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}
Export-ModuleMember -Function Get-NsxtEdgeNode

Function Get-NsxtTier0LocaleServiceBgp {
    <#
        .SYNOPSIS
        Get details for BGP in the locale services.

        .DESCRIPTION
        The Get-NsxtTier0LocaleServiceBgp cmdlet returns the details for BGP in the locale services.

        .EXAMPLE
        Get-NsxtTier0LocaleServiceBgp -id <guid>
        This example returns the details for BGP in the locale services.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$id
    )

    Try {
        $uri = "https://$nsxtmanager/policy/api/v1/infra/tier-0s/$id/locale-services/default/bgp"
        $response = Invoke-RestMethod -Method GET -Uri $uri -Headers $nsxtHeaders
        $response
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}
Export-ModuleMember -Function Get-NsxtTier0LocaleServiceBgp

Function Get-NsxtVidmStatus {
    <#
        .SYNOPSIS
        Get the status of the Identity Manager integration.

        .DESCRIPTION
        The Get-NsxtVidmStatus cmdlet returns the status of the Identity Manager integration.

        .EXAMPLE
        Get-NsxtVidmStatus
        This example returns the status of the Identity Manager integration.
    #>

    Try {
        $uri = "https://$nsxtManager/api/v1/node/aaa/providers/vidm/status"
        $response = Invoke-RestMethod $uri -Method 'GET' -Headers $nsxtHeaders
        $response
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}
Export-ModuleMember -Function Get-NsxtVidmStatus

Function Get-NsxtTransportNodeStatus {
    <#
        .SYNOPSIS
        Get the status of the NSX transport nodes.

        .DESCRIPTION
        The Get-NsxtTransportNodeStatus cmdlet returns the status of the transport nodes.

        .EXAMPLE
        Get-NsxtTransportNodeStatus
        This example returns the status of all transport nodes.

        .EXAMPLE
        Get-NsxtTransportNodeStatus -type edge
        This example returns the status of the edge transport nodes.

        .EXAMPLE
        Get-NsxtTransportNodeStatus -type host
        This example returns the status of the host transport nodes.   
    #>

    Param (
        [Parameter (Mandatory = $false)] [ValidateSet('host', 'edge')][ValidateNotNullOrEmpty()] [String]$type
    )

    Try {
        if ($PsBoundParameters.ContainsKey('type')) {
            $uri = "https://$nsxtManager/api/v1/transport-nodes/status?node_type=$($type.ToUpper())"
        } else {
            $uri = "https://$nsxtManager/api/v1/transport-nodes/status"
        }
        $response = Invoke-RestMethod $uri -Method 'GET' -Headers $nsxtHeaders
        $response
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}
Export-ModuleMember -Function Get-NsxtTransportNodeStatus

Function Get-NsxtComputeManagerStatus {
    <#
        .SYNOPSIS
        Get the status of a compute manager registered to the NSX Manager cluster.

        .DESCRIPTION
        The Get-NsxtComputeManagerStatus cmdlet returns the status of a compute manager registered to the NSX Manager cluster.

        .EXAMPLE
        Get-NsxtComputeManagerStatus -id <guid>
        This example returns the status of a compute manager registered to the NSX Manager cluster.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$id
    )

    Try {
        $uri = "https://$nsxtManager/api/v1/fabric/compute-managers/$id/status"
        $response = Invoke-RestMethod $uri -Method 'GET' -Headers $nsxtHeaders
        $response
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}
Export-ModuleMember -Function Get-NsxtComputeManagerStatus

##############################  End Supporting Functions ###############################
########################################################################################
