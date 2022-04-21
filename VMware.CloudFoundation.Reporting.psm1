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
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        Clear-Host; Write-Host ""

        if ($message = Test-VcfHealthPrereq) {Write-Warning $message; Write-Host ""; Break }
        if ($PsBoundParameters.ContainsKey("allDomains")) {
            $workflowMessage = "VMware Cloud Foundation instance ($sddcManagerFqdn)"
        } else {
            $workflowMessage = "Workload Domain ($workloadDomain)"
        }
        Start-SetupLogFile -Path $reportPath -ScriptName $MyInvocation.MyCommand.Name # Setup Log Location and Log File
        Write-LogMessage -Type INFO -Message "Starting the process of creating a Health Report for $workflowMessage." -Colour Yellow
        Write-LogMessage -Type INFO -Message "Setting up the log file to path $logfile."
        Start-CreateReportDirectory -path $reportPath -sddcManagerFqdn $sddcManagerFqdn -reportType health # Setup Report Location and Report File
        Write-LogMessage -Type INFO -Message "Setting up report folder and report $reportName."

        Write-LogMessage -Type INFO -Message "Running an SoS Health Check Collection for $workflowMessage, process takes time."
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
        Write-LogMessage -Type INFO -Message "Generating the NSX-T Data Center Health Report using the SoS output for $workflowMessage."
        if ($PsBoundParameters.ContainsKey("failureOnly")) {
            $serviceHtml = Publish-ServiceHealth -json $jsonFilePath -html -failureOnly
            $dnsHtml = Publish-DnsHealth -json $jsonFilePath -html -failureOnly
            $ntpHtml = Publish-NtpHealth -json $jsonFilePath -html -failureOnly
            $certificateHtml = Publish-CertificateHealth -json $jsonFilePath -html -failureOnly
            $esxiHtml = Publish-EsxiHealth -json $jsonFilePath -html -failureOnly
            $vsanHtml = Publish-VsanHealth -json $jsonFilePath -html -failureOnly
            $vsanPolicyHtml = Publish-VsanStoragePolicy -json $jsonFilePath -html -failureOnly
            $vcenterHtml = Publish-VcenterHealth -json $jsonFilePath -html -failureOnly
            $nsxtHtml = Publish-NsxtHealth -json $jsonFilePath -html -failureOnly
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
            $nsxtHtml = Publish-NsxtHealth -json $jsonFilePath -html
            $nsxtEdgeClusterHtml = Publish-NsxtEdgeClusterHealth -json $jsonFilePath -html
            $nsxtEdgeNodeHtml = Publish-NsxtEdgeNodeHealth -json $jsonFilePath -html
        }

        # Generating the Connectivity Health Data
        Write-LogMessage -Type INFO -Message "Generating the Connectivity Health Report using the SoS output for $workflowMessage."
        if ($PsBoundParameters.ContainsKey("allDomains")) { 
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                $componentConnectivityHtml = Publish-ComponentConnectivityHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -json $jsonFilePath -allDomains -failureOnly
            }
            else {
                $componentConnectivityHtml = Publish-ComponentConnectivityHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -json $jsonFilePath -allDomains
            }
        }
        else {
            if ($PsBoundParameters.ContainsKey("failureOnly")) { 
                $componentConnectivityHtml = Publish-ComponentConnectivityHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -json $jsonFilePath -workloadDomain $workloadDomain -failureOnly
            }
            else {
                $componentConnectivityHtml = Publish-ComponentConnectivityHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -json $jsonFilePath -workloadDomain $workloadDomain
            }
        }

        # Generating the Backup Status Health Data
        Write-LogMessage -Type INFO -Message "Generating the Backup Status Report for $workflowMessage."
        if ($PsBoundParameters.ContainsKey("allDomains")) { 
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                $backupStatusHtml = Publish-BackupStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains -failureOnly
            }
            else { 
                $backupStatusHtml = Publish-BackupStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains
            }
        }
        else {
            if ($PsBoundParameters.ContainsKey("failureOnly")) { 
                $backupStatusHtml = Publish-BackupStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain -failureOnly
            }
            else {
                $backupStatusHtml = Publish-BackupStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
            }
        }
        
        # Generating the Snapshot Status Health Data
        # TODO: Snapshot to be re-implemented to allow for -failureOnly.
        Write-LogMessage -type INFO -Message "Generating the Snapshots Report for $workflowMessage."
        if ($PsBoundParameters.ContainsKey('allDomains')) { 
            # if ($PsBoundParameters.ContainsKey('failureOnly')) {
            #     $snapshotStatusHtml = Publish-SnapshotStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains -failureOnly
            # }
            # else { 
            $snapshotStatusHtml = Publish-SnapshotStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains
            # }
        }
        else {
            # if ($PsBoundParameters.ContainsKey('failureOnly')) { 
            #     $snapshotStatusHtml = Publish-SnapshotStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain -failureOnly
            # }
            # else {
            $snapshotStatusHtml = Publish-SnapshotStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
            # }
        }

        # Generating the Password Expiry Health Data
        Write-LogMessage -Type INFO -Message "Generating the Password Expiry Report for $workflowMessage."
        if ($PsBoundParameters.ContainsKey("allDomains")) { 
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                $localPasswordHtml = Publish-LocalUserExpiry -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -sddcRootPass $sddcManagerRootPass -allDomains -failureOnly
            }
            else { 
                $localPasswordHtml = Publish-LocalUserExpiry -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -sddcRootPass $sddcManagerRootPass -allDomains
            }
        }
        else {
            if ($PsBoundParameters.ContainsKey("failureOnly")) { 
                $localPasswordHtml = Publish-LocalUserExpiry -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -sddcRootPass $sddcManagerRootPass -workloadDomain $workloadDomain -failureOnly
            }
            else {
                $localPasswordHtml = Publish-LocalUserExpiry -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -sddcRootPass $sddcManagerRootPass -workloadDomain $workloadDomain
            }
        }

        # Generating the NSX Tier-0 Gateway BGP Health Data
        Write-LogMessage -type INFO -Message "Generating the NSX Tier-0 Gateway BGP Report for $workflowMessage."
        if ($PsBoundParameters.ContainsKey('allDomains')) { 
            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                $nsxTier0BgpHtml = Publish-NsxtTier0BgpStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains -failureOnly
            }
            else { 
                $nsxTier0BgpHtml = Publish-NsxtTier0BgpStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains
            }
        }
        else {
            if ($PsBoundParameters.ContainsKey('failureOnly')) { 
                $nsxTier0BgpHtml = Publish-NsxtTier0BgpStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain -failureOnly
            }
            else {
                $nsxTier0BgpHtml = Publish-NsxtTier0BgpStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
            }
        }

        # Generating the Disk Capacity Health Data
        Write-LogMessage -Type INFO -Message "Generating the Disk Capacity Report for $workflowMessage.'"
        if ($PsBoundParameters.ContainsKey("allDomains")) { 
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                $storageCapacityHealthHtml = Publish-StorageCapacityHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -rootPass $sddcManagerRootPass -html -allDomains -failureOnly
            }
            else {
                $storageCapacityHealthHtml = Publish-StorageCapacityHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -rootPass $sddcManagerRootPass -html -allDomains
            }
        }
        else {
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                $storageCapacityHealthHtml = Publish-StorageCapacityHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -rootPass $sddcManagerRootPass -html -workloadDomain $workloadDomain -failureOnly
            }
            else {
                $storageCapacityHealthHtml = Publish-StorageCapacityHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -rootPass $sddcManagerRootPass -html -workloadDomain $workloadDomain
            }
        }

        # Combine all information gathered into a single HTML report
        if ($PsBoundParameters.ContainsKey("allDomains")) {
            $reportData = "<h1>SDDC Manager: $sddcManagerFqdn</h1>"
        } else {
            $reportData = "<h1>Workload Domain: $workloadDomain</h1>"
        }
        $reportData += "$serviceHtml $componentConnectivityHtml $localPasswordHtml $certificateHtml $backupStatusHtml $snapshotStatusHtml $dnsHtml $ntpHtml $vcenterHtml $esxiHtml $vsanHtml $vsanPolicyHtml $nsxtHtml $nsxtEdgeClusterHtml $nsxtEdgeNodeHtml $nsxTier0BgpHtml $storageCapacityHealthHtml"

        $reportHeader = Get-ClarityReportHeader
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
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        Clear-Host; Write-Host ""

        if ($message = Test-VcfHealthPrereq) {Write-Warning $message; Write-Host ""; Break }
        if ($PsBoundParameters.ContainsKey("allDomains")) {
            $workflowMessage = "VMware Cloud Foundation instance ($sddcManagerFqdn)"
        } else {
            $workflowMessage = "Workload Domain ($workloadDomain)"
        }
        Start-SetupLogFile -Path $reportPath -ScriptName $MyInvocation.MyCommand.Name # Setup Log Location and Log File
        Write-LogMessage -Type INFO -Message "Starting the process of creating an Alert Report for $workflowMessage." -Colour Yellow
        Write-LogMessage -Type INFO -Message "Setting up the log file to path $logfile."
        Start-CreateReportDirectory -path $reportPath -sddcManagerFqdn $sddcManagerFqdn -reportType alert # Setup Report Location and Report File
        Write-LogMessage -Type INFO -Message "Setting up report folder and report $reportName."  

        Write-LogMessage -Type INFO -Message "Generating the vCenter Server alerts for $workflowMessage."
        if ($PsBoundParameters.ContainsKey("allDomains")) { 
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                $vCenterAlertHtml = Publish-VcenterAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -alldomains -failureOnly
            }
            else {
                $vCenterAlertHtml = Publish-VcenterAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -alldomains
            }
        }
        else {
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                $vCenterAlertHtml = Publish-VcenterAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain -failureOnly
            }
            else {
                $vCenterAlertHtml = Publish-VcenterAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
            }
        }

        Write-LogMessage -type INFO -Message "Generating the ESXi host alerts for $workflowMessage."
        if ($PsBoundParameters.ContainsKey('allDomains')) { 
            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                $esxiAlertHtml = Publish-EsxiAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -alldomains -failureOnly
            }
            else {
                $esxiAlertHtml = Publish-EsxiAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -alldomains
            }
        }
        else {
            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                $esxiAlertHtml = Publish-EsxiAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain -failureOnly
            }
            else {
                $esxiAlertHtml = Publish-EsxiAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
            }
        }

        Write-LogMessage -type INFO -Message "Generating the vSAN alerts for $workflowMessage."
        if ($PsBoundParameters.ContainsKey('allDomains')) { 
            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                $vsanAlertHtml = Publish-VsanAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -alldomains -failureOnly
            }
            else {
                $vsanAlertHtml = Publish-VsanAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -alldomains
            }
        }
        else {
            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                $vsanAlertHtml = Publish-VsanAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain -failureOnly
            }
            else {
                $vsanAlertHtml = Publish-VsanAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
            }
        }

        Write-LogMessage -type INFO -Message "Generating the NSX-T Data Center alerts for $workflowMessage."
        if ($PsBoundParameters.ContainsKey('allDomains')) { 
            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                $nsxtAlertHtml = Publish-NsxtAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -alldomains -failureOnly
            }
            else {
                $nsxtAlertHtml = Publish-NsxtAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -alldomains
            }
        }
        else {
            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                $nsxtAlertHtml = Publish-NsxtAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain -failureOnly
            }
            else {
                $nsxtAlertHtml = Publish-NsxtAlert -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
            }
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

        $reportHeader = Get-ClarityReportHeader
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
        [Parameter (ParameterSetName = 'Specific--WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain
    )

    Try {
        Clear-Host; Write-Host ""

        if ($message = Test-VcfHealthPrereq) {Write-Warning $message; Write-Host ""; Break }
        if ($PsBoundParameters.ContainsKey("allDomains")) {
            $workflowMessage = "VMware Cloud Foundation instance ($sddcManagerFqdn)"
        } else {
            $workflowMessage = "Workload Domain ($workloadDomain)"
        }
        Start-SetupLogFile -Path $reportPath -ScriptName $MyInvocation.MyCommand.Name # Setup Log Location and Log File
        Write-LogMessage -Type INFO -Message "Starting the Process of Creating a Configuration Report for $workflowMessage." -Colour Yellow
        Write-LogMessage -Type INFO -Message "Setting up the log file to path $logfile"
        Start-CreateReportDirectory -path $reportPath -sddcManagerFqdn $sddcManagerFqdn -reportType config # Setup Report Location and Report File
        Write-LogMessage -Type INFO -Message "Setting up report folder and report $reportName"

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

        $reportHeader = Get-ClarityReportHeader
        $reportNavigation = Get-ClarityReportNavigation -reportType config
        $reportFooter = Get-ClarityReportFooter
        $report = $reportHeader
        $report += $reportNavigation
        $report += $reportData
        $report += $reportFooter

        # Generate the report to an HTML file and then open it in the default browser
        Write-LogMessage -Type INFO -Message "Generating the Final Report and Saving to ($reportName)"
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
        [Parameter (ParameterSetName = 'Specific--WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain
    )

    Try {

        Clear-Host; Write-Host ""

        if ($message = Test-VcfHealthPrereq) {Write-Warning $message; Write-Host ""; Break }
        $workflowMessage = "Workload Domain ($workloadDomain)"
        Start-SetupLogFile -Path $reportPath -ScriptName $MyInvocation.MyCommand.Name # Setup Log Location and Log File
        Write-LogMessage -Type INFO -Message "Starting the Process of Running an Upgrade Precheck for $workflowMessage." -Colour Yellow
        Write-LogMessage -Type INFO -Message "Setting up the log file to path $logfile"
        Start-CreateReportDirectory -path $reportPath -sddcManagerFqdn $sddcManagerFqdn -reportType upgrade # Setup Report Location and Report File
        Write-LogMessage -Type INFO -Message "Setting up report folder and report $reportName"

        if (Test-VCFConnection -server $sddcManagerFqdn) {
            if (Test-VCFAuthentication -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass) {
                $jsonSpec = '{ "resources" : [ { "resourceId" : "'+ (Get-VCFWorkloadDomain | Where-Object {$_.name -eq $workloadDomain}).id+'", "type" : "DOMAIN" } ] }'
                $task = Start-VCFSystemPrecheck -json $jsonSpec
                Write-LogMessage -Type INFO -Message "Waiting for Upgrade Precheck Task ($($task.name)) with Id ($($task.id)) to Complete"
                Do { $status = Get-VCFSystemPrecheckTask -id $task.id } While ($status.status -eq "IN_PROGRESS")
                Write-LogMessage -Type INFO -Message "Task ($($task.name)) with Task Id ($($task.id)) completed with status ($($status.status))"
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
                    $elementObject | Add-Member -NotePropertyName 'Status' -NotePropertyValue $subTask.status
                    $allChecksObject += $elementObject
                }
                $allChecksObject = $allChecksObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="upgrade-precheck"></a><h3>Upgrade Precheck</h3>' -As Table
                $allChecksObject = Convert-CssClass -htmldata $allChecksObject
            }
        }

        # Combine all information gathered into a single HTML report
        $reportData = "<h1>Workload Domain: $workloadDomain</h1>"
        $reportData += $allChecksObject

        $reportHeader = Get-ClarityReportHeader
        $reportNavigation = Get-ClarityReportNavigation -reportType upgrade
        $reportFooter = Get-ClarityReportFooter
        $report = $reportHeader
        $report += $reportNavigation
        $report += $reportData
        $report += $reportFooter

        # Generate the report to an HTML file and then open it in the default browser
        Write-LogMessage -Type INFO -Message "Generating the Final Report and Saving to ($reportName)"
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
        Invoke-VcfPasswordPolicy -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser admin@local -sddcManagerPass VMw@re1!VMw@re1! -reportPath F:\Reporting -workloadDomain sfo-w01
        This example runs a password policy report for a specific Workload Domain within an SDDC Manager instance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerFqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerUser,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerPass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$reportPath,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific--WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain
    )

    Try {

        Clear-Host; Write-Host ""

        if ($message = Test-VcfHealthPrereq) {Write-Warning $message; Write-Host ""; Break }
        Start-SetupLogFile -Path $reportPath -ScriptName $MyInvocation.MyCommand.Name # Setup Log Location and Log File
        Write-LogMessage -Type INFO -Message "Starting the Process of Running a Password Policy Report for VMware Cloud Foundation Instance ($sddcManagerFqdn)" -Colour Yellow
        Write-LogMessage -Type INFO -Message "Setting up the log file to path $logfile"
        Start-CreateReportDirectory -path $reportPath -sddcManagerFqdn $sddcManagerFqdn -reportType policy # Setup Report Location and Report File
        Write-LogMessage -Type INFO -Message "Setting up report folder and report $reportName"

        if ($PsBoundParameters.ContainsKey('allDomains')) { 
            Write-LogMessage -Type INFO -Message "Collecting ESXi Password Policy Configuration from SDDC Manager ($sddcManagerFqdn)"
            $sxiPolicyHtml = Publish-EsxiPasswordPolicy -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains
        }
        else {
            Write-LogMessage -Type INFO -Message "Collecting ESXi Password Policy Configuration for Workload Domain ($workloadDomain)"
            $sxiPolicyHtml = Publish-EsxiPasswordPolicy -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
        }
        
        # Combine all information gathered into a single HTML report
        if ($PsBoundParameters.ContainsKey("allDomains")) {
            $reportData = "<h1>SDDC Manager: $sddcManagerFqdn</h1>"
        } else{
            $reportData = "<h1>Workload Domain: $workloadDomain</h1>"
        }
        $reportData += $sxiPolicyHtml

        $reportHeader = Get-ClarityReportHeader
        $reportNavigation = Get-ClarityReportNavigation -reportType policy
        $reportFooter = Get-ClarityReportFooter
        $report = $reportHeader
        $report += $reportNavigation
        $report += $reportData
        $report += $reportFooter

        # Generate the report to an HTML file and then open it in the default browser
        Write-LogMessage -Type INFO -Message "Generating the Final Report and Saving to ($reportName)"
        $report | Out-File $reportName
        Invoke-Item $reportName
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Invoke-VcfPasswordPolicy

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
        [Parameter (ParameterSetName = 'Specific-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain
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
            # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        }
        else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
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
                $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="security-certificate"></a><h3>Certificate Health Status</h3>' -PostContent '<p>No Issues Found</p>' 
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
            # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        }
        else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }
        $customObject += $outputObject # Adding individual component to main customObject

        # ESXi API Status
        $jsonInputData = $targetContent.Connectivity.'Connectivity Status'.'ESXi API Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey('failureOnly')) {
            # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        }
        else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }
        $customObject += $outputObject # Adding individual component to main customObject

        # Additional Items Status
        $jsonInputData = $targetContent.Connectivity.'Connectivity Status' # Extract Data from the provided SOS JSON
        $jsonInputData.PSObject.Properties.Remove('ESXi SSH Status')
        $jsonInputData.PSObject.Properties.Remove('ESXi API Status')
        if ($PsBoundParameters.ContainsKey('failureOnly')) {
            # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        }
        else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }
        $customObject += $outputObject # Adding individual component to main customObject

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey('html')) {
            if ($outputObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="general-connectivity"></a><h3>Connectivity Health Status</h3>' -PostContent '<p>No Issues Found</p>' 
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
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $allForwardLookupObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $allForwardLookupObject = Read-JsonElement -inputData $jsonInputData
        }

        # Reverse Lookup Health Status
        $allReverseLookupObject = New-Object System.Collections.ArrayList
        $jsonInputData = $targetContent.'DNS lookup Status'.'Reverse lookup Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $allReverseLookupObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $allReverseLookupObject = Read-JsonElement -inputData $jsonInputData
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) { 
            if ($allForwardLookupObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $allForwardLookupObject = $allForwardLookupObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="infra-dns-forward"></a><h3>DNS Forward Lookup Health Status</h3>' -PostContent '<p>No Issues Found</p>' 
            } else {
                $allForwardLookupObject = $allForwardLookupObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="infra-dns-forward"></a><h3>DNS Forward Lookup Health Status</h3>' -As Table
            }
            $allForwardLookupObject = Convert-CssClass -htmldata $allForwardLookupObject
            $allForwardLookupObject
            if ($allReverseLookupObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $allReverseLookupObject = $allReverseLookupObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="infra-dns-reverse"></a><h3>DNS Reverse Lookup Health Status</h3>' -PostContent '<p>No Issues Found</p>' 
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
            # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $allOverallHealthObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        }
        else {
            $allOverallHealthObject = Read-JsonElement -inputData $jsonInputData
        }

        # ESXi Core Dump Status
        $allCoreDumpObject = New-Object System.Collections.ArrayList
        $jsonInputData = $targetContent.General.'ESXi Core Dump Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey('failureOnly')) {
            # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $allCoreDumpObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        }
        else {
            $allCoreDumpObject = Read-JsonElement -inputData $jsonInputData
        }
        
        # ESXi License Status
        $allLicenseObject = New-Object System.Collections.ArrayList
        $jsonInputData = $targetContent.Compute.'ESXi License Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey('failureOnly')) {
            # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $allLicenseObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        }
        else {
            $allLicenseObject = Read-JsonElement -inputData $jsonInputData
        }

        # ESXi Disk Status
        $allDiskObject = New-Object System.Collections.ArrayList
        $jsonInputData = $targetContent.Compute.'ESXi Disk Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey('failureOnly')) {
            # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $allDiskObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        }
        else {
            $allDiskObject = Read-JsonElement -inputData $jsonInputData
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey('html')) {
            if ($allOverallHealthObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $allOverallHealthObject = $allOverallHealthObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-overall"></a><h3>ESXi Overall Health Status</h3>' -PostContent '<p>No Issues Found</p>' 
            } else {
                $allOverallHealthObject = $allOverallHealthObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-overall"></a><h3>ESXi Overall Health Status</h3>' -As Table
            }
            $allOverallHealthObject = Convert-CssClass -htmldata $allOverallHealthObject
            $allOverallHealthObject

            if ($allCoreDumpObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $allCoreDumpObject = $allCoreDumpObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-coredump"></a><h3>ESXi Core Dump Health Status</h3>' -PostContent '<p>No Issues Found</p>' 
            } else {
                $allCoreDumpObject = $allCoreDumpObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-coredump"></a><h3>ESXi Core Dump Health Status</h3>' -As Table
            }
            $allCoreDumpObject = Convert-CssClass -htmldata $allCoreDumpObject
            $allCoreDumpObject

            if ($allLicenseObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $allLicenseObject = $allLicenseObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-license"></a><h3>ESXi License Health Status</h3>' -PostContent '<p>No Issues Found</p>' 
            } else {
                $allLicenseObject = $allLicenseObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-license"></a><h3>ESXi License Health Status</h3>' -As Table
            }
            $allLicenseObject = Convert-CssClass -htmldata $allLicenseObject
            $allLicenseObject

            if ($allDiskObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $allDiskObject = $allDiskObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-disk"></a><h3>ESXi Disk Health Status</h3>' -PostContent '<p>No Issues Found</p>' 
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

        # # NSX Edge Health
        # $component = 'NSX Edge'
        # $nsxtClusters = Get-VCFNsxtCluster
        # $inputData = $targetContent.General.'NSX Health'.'NSX Edge'
        # foreach ($nsxtVip in $nsxtClusters.vipFqdn) {
        #     $inputData.PSObject.Properties.Remove($nsxtVip)
        # }
        # foreach ($element in $inputData.PsObject.Properties.Value) {
        #     $elementObject = New-Object -TypeName psobject
        #     $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component
        #     $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue ($element.area -Split (':'))[-1].Trim()
        #     $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $element.alert
        #     $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $element.message
        #     if ($PsBoundParameters.ContainsKey('failureOnly')) {
        #         if (($element.status -eq 'FAILED')) {
        #             $customObject += $elementObject
        #         }
        #     }
        #     else {
        #         $customObject += $elementObject
        #     }
        # }

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
                $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="nsx-local-manager"></a><h3>NSX Manager Health Status</h3>' -PostContent '<p>No Issues Found</p>' 
            } else {
                $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="nsx-local-manager"></a><h3>NSX Manager Health Status</h3>' -As Table
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
                $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="nsx-edge"></a><h3>NSX Edge Node Health Status</h3>' -PostContent '<p>No Issues Found</p>' 
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
                $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="nsx-edge-cluster"></a><h3>NSX Edge Cluster Health Status</h3>' -PostContent '<p>No Issues Found</p>' 
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

        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) { 
            if ($outputObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="infra-ntp"></a><h3>NTP Health Status</h3>' -PostContent '<p>No Issues Found</p>' 
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
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) { 
            if ($outputObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="security-password"></a><h3>Password Expiry Health Status</h3>' -PostContent '<p>No Issues Found</p>' 
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
                $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="general-service"></a><h3>Service Health Status</h3>' -PostContent '<p>No Issues Found</p>' 
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
            # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $vcenterOverall = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $vcenterOverall = Read-JsonElement -inputData $jsonInputData
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
                $vcenterOverall = $vcenterOverall | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="vcenter-overall"></a><h3>vCenter Server Overall Health Status</h3>' -PostContent '<p>No Issues Found</p>' 
            } else {
                $vcenterOverall = $vcenterOverall | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="vcenter-overall"></a><h3>vCenter Server Overall Health Status</h3>' -As Table
            }
            $vcenterOverall = Convert-CssClass -htmldata $vcenterOverall
            $vcenterOverall

            if ($ringTopologyHealth.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $ringTopologyHealth = $ringTopologyHealth | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="vcenter-ring"></a><h3>vCenter Single Sign-On Ring Topology Health Status</h3>' -PostContent '<p>No Issues Found</p>' 
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
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }
        $customObject += $outputObject # Adding individual component to main customObject
        
        # Cluster Disk Status
        $jsonInputData = $targetContent.VSAN.'Cluster Disk Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }
        $customObject += $outputObject # Adding individual component to main customObject

        # Cluster Data Compression Status
        $jsonInputData = $targetContent.VSAN.'Cluster Data Compression Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }
        $customObject += $outputObject # Adding individual component to main customObject

        # Cluster Data Encryption Status
        $jsonInputData = $targetContent.VSAN.'Cluster Data Encryption Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }
        $customObject += $outputObject # Adding individual component to main customObject

        # Cluster Data Deduplication Status
        $jsonInputData = $targetContent.VSAN.'Cluster Data Deduplication Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }
        $customObject += $outputObject # Adding individual component to main customObject

        # Stretched Cluster Status
        $jsonInputData = $targetContent.VSAN.'Stretched Cluster Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }
        $customObject += $outputObject # Adding individual component to main customObject

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) { 
            if ($customObject.Count -eq 0) { $addNoIssues = $true }
            if ($addNoIssues) {
                $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="vsan-overall"></a><h3>vSAN Overall Health Status</h3>' -PostContent '<p>No Issues Found</p>' 
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
                $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="vsan-spbm"></a><h3>vSAN Storage Policy Health Status</h3>' -PostContent '<p>No Issues Found</p>' 
            } else {
                $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="vsan-spbm"></a><h3>vSAN Storage Policy Health Status</h3>' -As Table
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
        The Publish-BackupStatus cmdlet checks the backup status for SDDC Manager, vCenter Server instances,
        and NSX Local Manager clusters in a VMware Cloud Foundation instance and prepares the data to be published
        to an HTML report. The cmdlet connects to SDDC Manager using the -server, -user, and password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Performs checks on the backup status and outputs the results

        .EXAMPLE
        Publish-BackupStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will publish the backup status for the SDDC Manager, vCenter Server instances, and NSX Local Manager clusters in a VMware Cloud Foundation instance.  

        .EXAMPLE
        Publish-BackupStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -failureOnly
        This example will publish the backup status for the SDDC Manager, vCenter Server instances, and NSX Local Manager clusters in a VMware Cloud Foundation instance but only for the failed items.
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
                        $allBackupStatusObject = $allBackupStatusObject | Sort-Object Component, Resource, Element | ConvertTo-Html -Fragment -PreContent '<a id="infra-backup"></a><h3>Backups Status</h3>' -PostContent "<p>No Issues Found</p>" 
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

Function Publish-NsxtTier0BgpStatus {
    <#
		.SYNOPSIS
        Request and publish the BGP status for the NSX Tier-0 gateways.

        .DESCRIPTION
        The Publish-NsxtTier0BgpStatus cmdlet checks the BGP status for the NSX Tier-0 gateways in a
        VMware Cloud Foundation instance and prepares the data to be published to an HTML report. 
        The cmdlet connects to SDDC Manager using the -server, -user, and password values:
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
                $singleWorkloadDomain = Get-VCFWorkloadDomain | Where-Object { $_.name -eq $workloadDomain }
                $allNsxtTier0BgpStatusObject = New-Object System.Collections.ArrayList

                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                    if ($PsBoundParameters.ContainsKey('allDomains')) {
                        foreach ($domain in $allWorkloadDomains ) {
                            $nsxtTier0BgpStatus = Request-NsxtTier0BgpStatus -server $server -user $user -pass $pass -domain $domain.name -failureOnly; $allNsxtTier0BgpStatusObject += $nsxtTier0BgpStatus
                        }
                    }
                    else {
                        $nsxtTier0BgpStatus = Request-NsxtTier0BgpStatus -server $server -user $user -pass $pass -domain $domain.name -failureOnly; $allNsxtTier0BgpStatusObject += $nsxtTier0BgpStatus
                    }
                }
                else {
                    if ($PsBoundParameters.ContainsKey('allDomains')) { 
                        foreach ($domain in $allWorkloadDomains ) {
                            $nsxtTier0BgpStatus = Request-NsxtTier0BgpStatus -server $server -user $user -pass $pass -domain $domain.name; $allNsxtTier0BgpStatusObject += $nsxtTier0BgpStatus
                        }
                    }
                    else {
                        $nsxtTier0BgpStatus = Request-NsxtTier0BgpStatus -server $server -user $user -pass $pass -domain $workloadDomain; $allNsxtTier0BgpStatusObject += $nsxtTier0BgpStatus
                    }
                }

                if ($allNsxtTier0BgpStatusObject.Count -eq 0) {
                    $addNoIssues = $true 
                }
                if ($addNoIssues) {
                    $allNsxtTier0BgpStatusObject = $allNsxtTier0BgpStatusObject | Sort-Object 'NSX Manager', 'Domain', 'Tier-0 ID', 'Source Address' | ConvertTo-Html -Fragment -PreContent '<a id="nsx-t0-bgp"></a><h3>NSX Tier-0 Gateway BGP Status</h3>' -PostContent '<p>No Issues Found</p>' 
                }
                else {
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
    #>

    # TODO: Snapshots status to be re-implemented with simple helper functions and mid-tier request functions.

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain
    )

    Try {

        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT)) {
                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {  
                            
                            $allSnapshotStatusObject = New-Object System.Collections.ArrayList
                            if ($PsBoundParameters.ContainsKey('allDomains')) { 
                                # Get the snapshot status for the SDDC Manager
                                $sddcManagerSnapshotStatus = Get-SnapshotStatus -vm ($server.Split('.')[0]); $allSnapshotStatusObject += $sddcManagerSnapshotStatus
                                
                                # Get the snapshot status for all vCenter Server instances in all workload domains
                                $allVcenters = Get-VCFvCenter
                                foreach ($vcenter in $allVcenters) {
                                    $vcenterSnapshotStatus = Get-SnapshotStatus -vm ($vcenter.fqdn.Split('.')[0]); $allSnapshotStatusObject += $vcenterSnapshotStatus
                                }
                                
                                # Get the snapshot status for all NSX Edge nodes in all workload domains
                                $allNsxtManagers = Get-VCFNsxtCluster
                                foreach ($nsxtManager in $allNsxtManagers) {
                                    if (($vcfNsxEdgeDetails = Get-VCFEdgeCluster | Where-Object { $_.nsxtCluster.vipFQDN -eq $nsxtManager.vipFQDN })) {   
                                        foreach ($nsxtEdgeNode in $vcfNsxEdgeDetails.edgeNodes) {
                                            if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $nsxtManager.domains.name)) {
                                                if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                                                    if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) { 
                                                        $nsxtEdgeSnapshotStatus = Get-SnapshotStatus -vm ($nsxtEdgeNode.hostName.Split('.')[0]); $allSnapshotStatusObject += $nsxtEdgeSnapshotStatus 
                                                    }
                                                }
                                            }     
                                        }
                                    }
                                }
                            }
                            else {
                                # Get the snapshot status for the vCenter Server instance for the specific workload domain
                                $vcenter = Get-VCFWorkloadDomain | Where-Object { $_.name -eq $workloadDomain }
                                $vcenterSnapshotStatus = Get-SnapshotStatus -vm ($vcenter.vcenters.fqdn.Split('.')[0]); $allSnapshotStatusObject += $vcenterSnapshotStatus

                                # Get the snapshot status for the NSX Edge nodes for the specific workload domain
                                $nsxtManager = Get-VCFNsxtCluster | Where-Object { $_.domains.name -eq $workloadDomain }
                                if ($nsxtEdgeDetails = Get-VCFEdgeCluster | Where-Object { $_.nsxtCluster.vipfqdn -eq $nsxtManager.vipFqdn }) {   
                                    foreach ($nsxtEdgeNode in $nsxtEdgeDetails.edgeNodes) {
                                        if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $nsxtManager.domains.name)) {
                                            if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                                                if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) { 
                                                    $nsxtEdgeSnapshotStatus = Get-SnapshotStatus -vm ($nsxtEdgeNode.hostName.Split('.')[0]); $allSnapshotStatusObject += $nsxtEdgeSnapshotStatus 
                                                }
                                            }
                                        }    
                                    }
                                }
                            }

                            # Return the structured data to the console or format using HTML CSS Styles
                            $allSnapshotStatusObject = $allSnapshotStatusObject | Sort-Object 'Virtual Machine', 'Created' | ConvertTo-Html -Fragment -PreContent '<a id="infra-snapshot"></a><h3>Snapshot Status</h3><p>By default, snapshots for NSX Local Manager cluster appliances are disabled and are not recommended.</p>' -As Table
                            $allSnapshotStatusObject = Convert-CssClass -htmldata $allSnapshotStatusObject
                            $allSnapshotStatusObject
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
            $allPasswordExpiryObject = $allPasswordExpiryObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="security-password"></a><h3>Password Expiry Health Status</h3>' -PostContent '<p>No Issues Found</p>' 
        } else {
            $allPasswordExpiryObject = $allPasswordExpiryObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="security-password"></a><h3>Password Expiry Health Status</h3>' -As Table
        }
        $allPasswordExpiryObject = Convert-CssClass -htmldata $allPasswordExpiryObject
        $allPasswordExpiryObject
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-LocalUserExpiry

Function Publish-StorageCapacityHealth {
    <#
		.SYNOPSIS
        Request and publish the storage capacity status.

        .DESCRIPTION
        The Publish-StorageCapacityHealth cmdlet checks the storage usage status for SDDC Manager, vCenter Server, 
        Datastores and ESXi hosts, in a VMware Cloud Foundation instance and prepares the data to be published
        to an HTML report or plain text to console. The cmdlet connects to SDDC Manager using the -server, -user, -password and -rootPass values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Performs checks on the storage usage status and outputs the results

        .EXAMPLE
        Publish-StorageCapacityHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -rootPass VMw@re1!VMw@re1! -html -allDomains
        This example will publish storage usage status for SDDC Manager, vCenter Server instances, ESXi hosts, and datastores in a VMware Cloud Foundation instance  

        .EXAMPLE
        Publish-StorageCapacityHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -rootPass VMw@re1!VMw@re1! -allDomains -failureOnly
        This example will publish storage usage status for SDDC Manager, vCenter Server instances, ESXi hosts, and datastores in a VMware Cloud Foundation instance but only for the failed items.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$rootPass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html
    )

    Try {
        $allStorageCapacityHealth = New-Object System.Collections.ArrayList
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                # Compose commands for different options

                $vCenterStorageHealthHeader = '<a id="storage-vcenter"></a><h3>vCenter Server Disk Health Status</h3>' # Adding the vCenter Server Disk Health Status header for report navigation.
                $esxiStorageCapacityHeader = '<a id="storage-esxi"></a><h3>ESXi Disk Health Status</h3>' # Adding the ESXi Disk Health Status header for report navigation.

                if ($PsBoundParameters.ContainsKey("allDomains")) {
                    if (($PsBoundParameters.ContainsKey("html")) -and ($PsBoundParameters.ContainsKey("failureOnly"))) { 
                        $sddcManagerStorageHealth = Request-SddcManagerStorageHealth -server $server -user $user -pass $pass -rootPass $rootPass -html -failureOnly ; $allStorageCapacityHealth += $sddcManagerStorageHealth
                        $vCenterStorageHealth = Request-VcenterStorageHealth -server $server -user $user -pass $pass -allDomains -html -failureOnly ; $allStorageCapacityHealth += $vCenterStorageHealthHeader += $vCenterStorageHealth
                        $datastoreStorageCapacity = Request-DatastoreStorageCapacity -server $server -user $user -pass $pass -allDomains -html -failureOnly ; $allStorageCapacityHealth += $datastoreStorageCapacity
                        $esxiStorageCapacity = Request-EsxiStorageCapacity -server $server -user $user -pass $pass -allDomains -html -failureOnly ; $allStorageCapacityHealth += $esxiStorageCapacityHeader += $esxiStorageCapacity
                    }
                    elseif ($PsBoundParameters.ContainsKey("html")) {
                        $sddcManagerStorageHealth = Request-SddcManagerStorageHealth -server $server -user $user -pass $pass -rootPass $rootPass -html ; $allStorageCapacityHealth += $sddcManagerStorageHealth
                        $vCenterStorageHealth = Request-VcenterStorageHealth -server $server -user $user -pass $pass -allDomains -html ; $allStorageCapacityHealth += $vCenterStorageHealthHeader += $vCenterStorageHealth
                        $datastoreStorageCapacity = Request-DatastoreStorageCapacity -server $server -user $user -pass $pass -allDomains -html ; $allStorageCapacityHealth += $datastoreStorageCapacity
                        $esxiStorageCapacity = Request-EsxiStorageCapacity -server $server -user $user -pass $pass -allDomains -html ; $allStorageCapacityHealth += $esxiStorageCapacityHeader += $esxiStorageCapacity
                    }
                    elseif ($PsBoundParameters.ContainsKey("failureOnly")) {
                        $sddcManagerStorageHealth = Request-SddcManagerStorageHealth -server $server -user $user -pass $pass -rootPass $rootPass -failureOnly ; $allStorageCapacityHealth += $sddcManagerStorageHealth
                        $vCenterStorageHealth = Request-VcenterStorageHealth -server $server -user $user -pass $pass -allDomains -failureOnly ; $allStorageCapacityHealth += $vCenterStorageHealthHeader += $vCenterStorageHealth
                        $datastoreStorageCapacity = Request-DatastoreStorageCapacity -server $server -user $user -pass $pass -allDomains -failureOnly ; $allStorageCapacityHealth += $datastoreStorageCapacity
                        $esxiStorageCapacity = Request-EsxiStorageCapacity -server $server -user $user -pass $pass -allDomains -failureOnly ; $allStorageCapacityHealth += $esxiStorageCapacityHeader += $esxiStorageCapacity
                    }
                    else {
                        $sddcManagerStorageHealth = Request-SddcManagerStorageHealth -server $server -user $user -pass $pass -rootPass $rootPass ; $allStorageCapacityHealth += $sddcManagerStorageHealth
                        $vCenterStorageHealth = Request-VcenterStorageHealth -server $server -user $user -pass $pass -allDomains ; $allStorageCapacityHealth += $vCenterStorageHealthHeader += $vCenterStorageHealth
                        $datastoreStorageCapacity = Request-DatastoreStorageCapacity -server $server -user $user -pass $pass -allDomains ; $allStorageCapacityHealth += $datastoreStorageCapacity
                        $esxiStorageCapacity = Request-EsxiStorageCapacity -server $server -user $user -pass $pass -allDomains ; $allStorageCapacityHealth += $esxiStorageCapacityHeader += $esxiStorageCapacity
                    }
                } else {
                    if (($PsBoundParameters.ContainsKey("html")) -and ($PsBoundParameters.ContainsKey("failureOnly"))) { 
                        $sddcManagerStorageHealth = Request-SddcManagerStorageHealth -server $server -user $user -pass $pass -rootPass $rootPass -html -failureOnly ; $allStorageCapacityHealth += $sddcManagerStorageHealth
                        $vCenterStorageHealth = Request-VcenterStorageHealth -server $server -user $user -pass $pass -workloadDomain $workloadDomain -html -failureOnly ; $allStorageCapacityHealth += $vCenterStorageHealthHeader += $vCenterStorageHealth
                        $datastoreStorageCapacity = Request-DatastoreStorageCapacity -server $server -user $user -pass $pass -workloadDomain $workloadDomain -html -failureOnly ; $allStorageCapacityHealth += $datastoreStorageCapacity
                        $esxiStorageCapacity = Request-EsxiStorageCapacity -server $server -user $user -pass $pass -workloadDomain $workloadDomain -html -failureOnly ; $allStorageCapacityHealth += $esxiStorageCapacityHeader += $esxiStorageCapacity
                    }
                    elseif ($PsBoundParameters.ContainsKey("html")) {
                        $sddcManagerStorageHealth = Request-SddcManagerStorageHealth -server $server -user $user -pass $pass -rootPass $rootPass -html ; $allStorageCapacityHealth += $sddcManagerStorageHealth
                        $vCenterStorageHealth = Request-VcenterStorageHealth -server $server -user $user -pass $pass -workloadDomain $workloadDomain -html ; $allStorageCapacityHealth += $vCenterStorageHealthHeader += $vCenterStorageHealth
                        $datastoreStorageCapacity = Request-DatastoreStorageCapacity -server $server -user $user -pass $pass -workloadDomain $workloadDomain -html ; $allStorageCapacityHealth += $datastoreStorageCapacity
                        $esxiStorageCapacity = Request-EsxiStorageCapacity -server $server -user $user -pass $pass -workloadDomain $workloadDomain -html ; $allStorageCapacityHealth += $esxiStorageCapacityHeader += $esxiStorageCapacity
                    }
                    elseif ($PsBoundParameters.ContainsKey("failureOnly")) {
                        $sddcManagerStorageHealth = Request-SddcManagerStorageHealth -server $server -user $user -pass $pass -rootPass $rootPass -failureOnly ; $allStorageCapacityHealth += $sddcManagerStorageHealth
                        $vCenterStorageHealth = Request-VcenterStorageHealth -server $server -user $user -pass $pass -workloadDomain $workloadDomain -failureOnly ; $allStorageCapacityHealth += $vCenterStorageHealthHeader += $vCenterStorageHealth
                        $datastoreStorageCapacity = Request-DatastoreStorageCapacity -server $server -user $user -pass $pass -workloadDomain $workloadDomain -failureOnly ; $allStorageCapacityHealth += $datastoreStorageCapacity
                        $esxiStorageCapacity = Request-EsxiStorageCapacity -server $server -user $user -pass $pass -workloadDomain $workloadDomain -failureOnly ; $allStorageCapacityHealth += $esxiStorageCapacityHeader += $esxiStorageCapacity
                    }
                    else {
                        $sddcManagerStorageHealth = Request-SddcManagerStorageHealth -server $server -user $user -pass $pass -rootPass $rootPass ; $allStorageCapacityHealth += $sddcManagerStorageHealth
                        $vCenterStorageHealth = Request-VcenterStorageHealth -server $server -user $user -pass $pass -workloadDomain $workloadDomain ; $allStorageCapacityHealth += $vCenterStorageHealthHeader += $vCenterStorageHealth
                        $datastoreStorageCapacity = Request-DatastoreStorageCapacity -server $server -user $user -pass $pass -workloadDomain $workloadDomain ; $allStorageCapacityHealth += $datastoreStorageCapacity
                        $esxiStorageCapacity = Request-EsxiStorageCapacity -server $server -user $user -pass $pass -workloadDomain $workloadDomain ; $allStorageCapacityHealth += $esxiStorageCapacityHeader += $esxiStorageCapacity
                    }
                }

                # Return Storage capacity usage:
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
        Request-SddcManagerUserExpiry -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -rootPass VMw@re1! -html
        This example checks the expiry for all local OS users in the SDDC Manager appliance and outputs in HTML format.

        .EXAMPLE
        Request-SddcManagerUserExpiry -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -rootPass VMw@re1! -failureOnly
        This example checks the expiry for all local OS users in the SDDC Manager appliance but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$rootPass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
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

                            # Return the structured data to the console or format using HTML CSS Styles
                            if ($PsBoundParameters.ContainsKey("html")) { 
                                $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h2>Password Expiry Health Status</h2>" -As Table
                                $customObject = Convert-CssClass -htmldata $customObject
                                $customObject
                            } else {
                                $customObject | Sort-Object Component, Resource 
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
        Request-NsxtEdgeUserExpiry -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-m01
        This example checks the expiry for local OS users for the NSX Edge node appliances for a specific workload domain.

        .EXAMPLE
        Request-NsxtEdgeUserExpiry -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-m01 -failureOnly
        This example checks the expiry for local OS users for the NSX Edge node appliances for a specific workload domain but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
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

                                    # Return the structured data to the console or format using HTML CSS Styles
                                    if ($PsBoundParameters.ContainsKey('html')) { 
                                        $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<h2>Password Expiry Health Status</h2>' -As Table
                                        $customObject = Convert-CssClass -htmldata $customObject
                                        $customObject
                                    }
                                    else {
                                        $customObject | Sort-Object Component, Resource 
                                    }
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
        Request-NsxtManagerUserExpiry -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-m01
        This example checks the expiry for local OS users for the NSX Manager appliances for a specific workload domain.

        .EXAMPLE
        Request-NsxtManagerUserExpiry -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-m01 -failureOnly
        This example checks the expiry for local OS users for the NSX Manager appliances for a specific workload domain but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
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
                                        $rootPass = (Get-VCFCredential | Where-Object { $_.credentialType -eq 'SSH' -and $_.resource.resourceName -eq $vcfNsxDetails.fqdn }).password
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

                                    # Return the structured data to the console or format using HTML CSS Styles
                                    if ($PsBoundParameters.ContainsKey("html")) { 
                                        $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h2>Password Expiry Health Status</h2>" -As Table
                                        $customObject = Convert-CssClass -htmldata $customObject
                                        $customObject
                                    } else {
                                        $customObject | Sort-Object Component, Resource 
                                    }
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
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
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
                                    }
                                    else {
                                        $customObject += $elementObject
                                    }
                                }
                            }
                            else {
                                $vcenter = (Get-VCFWorkloadDomain | Where-Object {$_.name -eq $workloadDomain}).vcenters.fqdn
                                $rootPass = (Get-VCFCredential | Where-Object {$_.credentialType -eq "SSH" -and $_.resource.resourceName -eq $vcenter}).password
                                $elementObject = Request-LocalUserExpiry -fqdn $vcenter -component vCenter -rootPass $rootPass -checkUser root
                                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                    if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                        $customObject += $elementObject
                                    }
                                }
                                else {
                                    $customObject += $elementObject
                                }
                            }

                            # Return the structured data to the console or format using HTML CSS Styles
                            if ($PsBoundParameters.ContainsKey("html")) { 
                                $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>Password Expiry Health Status</h3>" -As Table
                                $customObject = Convert-CssClass -htmldata $customObject
                                $customObject
                            } else {
                                $customObject | Sort-Object Component, Resource 
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
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
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
                            }
                            else {
                                $customObject += $elementObject
                            }

                            # Return the structured data to the console or format using HTML CSS Styles
                            if ($PsBoundParameters.ContainsKey("html")) { 
                                $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h2>Password Expiry Health Status</h2>" -As Table
                                $customObject = Convert-CssClass -htmldata $customObject
                                $customObject
                            } else {
                                $customObject | Sort-Object Component, Resource 
                            }
                        }
                    }
                    Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                }
            }
        }
    }
}
Export-ModuleMember -Function Request-vRslcmUserExpiry

Function Request-SddcManagerBackupStatus {
    <#
        .SYNOPSIS
        Returns the status of the file-level latest backup task in an SDDC Manager instance.

        .DESCRIPTION
        The Request-SddcManagerBackupStatus cmdlet returns the status of the latest file-level backup task in an SDDC
        Manager instance. The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Gathers the details for the SDDC Manager
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
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $backupTasks = Get-VCFTask | Where-Object { $_.type -eq 'SDDCMANAGER_BACKUP' } | Select-Object -First 1
                foreach ($backupTask in $backupTasks) {
                    $component = 'SDDC Manager' # Define the component name
                    $date = [DateTime]::ParseExact($backupTask.creationTimestamp, 'yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture) # Define the date
                    $domain = (Get-VCFWorkloadDomain | Sort-Object -Property type, name).name -join ',' # Define the domain(s)
                    $resource = $backupTask.name # Define the resource name
                    $backupAge = [math]::Ceiling(((Get-Date) - ([DateTime]$date)).TotalDays) # Calculate the number of days since the backup was created

                    $customObject = New-Object System.Collections.ArrayList

                    # Set the status for the backup task
                    if ($backupTask.status -eq 'Successful') {                              
                        $alert = "GREEN" # Ok; success
                    }
                    else {
                        $alert = "RED" # Critical; failure
                    }

                    # Set the message for the backup task
                    if ([string]::IsNullOrEmpty($errors)) {
                        $message = "The backup completed without errors. " # Ok; success
                    }
                    else {
                        $message = "The backup failed with errors. Please investigate before proceeding. " # Critical; failure
                    }

                    # Set the alert and message for the backup task based on the age of the backup
                    if ($backupAge -ge 3) {
                        $alert = "RED" # Critical; >= 3 days
                        $messageAge = "Backup is more than 3 days old." # Set the alert message
                    }
                    elseif ($backupAge -gt 1) {
                        $alert = "YELLOW" # Warning; > 1 days
                        $messageBackupAge = "Backup is more than 1 days old." # Set the alert message
                    }
                    else {
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
                    }
                    else {
                        $customObject += $elementObject
                    }  
                }

                $outputObject += $customObject # Add the custom object to the output object

                # Return the structured data to the console or format using HTML CSS Styles
                if ($PsBoundParameters.ContainsKey("html")) { 
                    if ($outputObject.Count -eq 0) { $addNoIssues = $true }
                    if ($addNoIssues) {
                        $outputObject = $outputObject | Sort-Object Component, Resource, Element | ConvertTo-Html -Fragment -PreContent '<a id="infra-backups"></a><h3>Backup Status</h3>' -PostContent '<p>No Issues Found</p>' 
                    }
                    else {
                        $outputObject = $outputObject | Sort-Object Component, Resource, Element | ConvertTo-Html -Fragment -PreContent '<a id="infra-backups"></a><h3>Backup Status</h3>' -As Table
                    }
                    $outputObject = Convert-CssClass -htmldata $outputObject
                    $outputObject
                }
                else {
                    $outputObject | Sort-Object Component, Resource, Element
                }
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
        The cmdlet connects to the NSX-T Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the NSX-T Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Gathers the details for the NSX Manager cluster
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
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfNsxDetails = Get-NsxtServerDetail -fqdn $server -username $user -password $pass -domain $domain)) {
                    if (Test-NSXTConnection -server $vcfNsxDetails.fqdn) {
                        if (Test-NSXTAuthentication -server $vcfNsxDetails.fqdn -user $vcfNsxDetails.adminUser -pass $vcfNsxDetails.adminPass) {
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
                                }
                                else {
                                    $alert = "RED" # Critical; failure
                                    $message = "The backup failed with errors. Please investigate before proceeding. " # Critical; failure
                                }

                                # Set the alert and message update for the backup task based on the age of the backup
                                if ($backupAge -ge 3) {
                                    $alert = 'RED' # Critical; >= 3 days
                                    $messageBackupAge = 'Backup is more than 3 days old.' # Set the alert message
                                }
                                elseif ($backupAge -gt 1) {
                                    $alert = 'YELLOW' # Warning; > 1 days
                                    $messageBackupAge = 'Backup is more than 1 days old.' # Set the alert message
                                }
                                else {
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
                                }
                                else {
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
                                }
                                else {
                                    $alert = 'RED' # Critical; failure
                                    $message = 'The backup failed with errors. Please investigate before proceeding. ' # Critical; failure
                                }

                                # Set the alert and message update for the backup task based on the age of the backup
                                if ($backupAge -ge 3) {
                                    $alert = 'RED' # Critical; >= 3 days
                                    $messageBackupAge = 'Backup is more than 3 days old.' # Set the alert message
                                }
                                elseif ($backupAge -gt 1) {
                                    $alert = 'YELLOW' # Warning; > 1 days
                                    $messageBackupAge = 'Backup is more than 1 days old.' # Set the alert message
                                }
                                else {
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
                                }
                                else {
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
                                }
                                else {
                                    $alert = 'RED' # Critical; failure
                                    $message = 'The backup failed with errors. Please investigate before proceeding. ' # Critical; failure
                                }

                                # Set the alert and message update for the backup task based on the age of the backup
                                if ($backupAge -ge 3) {
                                    $alert = 'RED' # Critical; >= 3 days
                                    $messageBackupAge = 'Backup is more than 3 days old.' # Set the alert message
                                }
                                elseif ($backupAge -gt 1) {
                                    $alert = 'YELLOW' # Warning; > 1 days
                                    $messageBackupAge = 'Backup is more than 1 days old.' # Set the alert message
                                }
                                else {
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
                                }
                                else {
                                    $customObject += $elementObject
                                }  
                            }

                            $outputObject += $customObject # Add the custom object to the output object

                            # Return the structured data to the console or format using HTML CSS Styles
                            if ($PsBoundParameters.ContainsKey('html')) { 
                                if ($outputObject.Count -eq 0) {
                                    $addNoIssues = $true 
                                }
                                if ($addNoIssues) {
                                    $outputObject = $outputObject | Sort-Object Component, Resource, Element | ConvertTo-Html -Fragment -PreContent '<a id="infra-backups"></a><h3>Backup Status</h3>' -PostContent '<p>No Issues Found</p>' 
                                }
                                else {
                                    $outputObject = $outputObject | Sort-Object Component, Resource, Element | ConvertTo-Html -Fragment -PreContent '<a id="infra-backups"></a><h3>Backup Status</h3>' -As Table
                                }
                                $outputObject = Convert-CssClass -htmldata $outputObject
                                $outputObject
                            }
                            else {
                                $outputObject | Sort-Object Component, Resource, Element
                            }                    
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
        The cmdlet connects to the NSX Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the NSX-T Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Gathers the details for the vCenter Server instance.
        - Collects the file-level backup status details

        .EXAMPLE
        Request-VcenterBackupStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return the status of the latest file-level backup of a vCenter Server instance managed by SDDC Manager for a workload domain.

        .EXAMPLE
        Request-VcenterBackupStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return the status of the latest file-level backup of a vCenter Server instance managed by SDDC Manager for a workload domain but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
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

                            $component = 'vCenter Server' # Define the component name
                            $resource = 'vCenter Server Backup Operation' # Define the resource name
                            $timestamp = $backupTask.end_time # Define the end timestamp
                            $backupAge = [math]::Ceiling(((Get-Date) - ([DateTime]$timestamp)).TotalDays) # Calculate the number of days since the backup was created

                            $customObject = New-Object System.Collections.ArrayList

                            # Set the status for the backup task
                            if ($backupTask.state -eq 'SUCCEEDED') {                              
                                $alert = "Green" # Ok; success
                            }
                            elseif ($backupTask.state -eq 'IN PROGRESS') {                              
                                $alert = "YELLOW" # Warning; in progress
                            }
                            else {
                                $alert = "RED" # Critical; failure
                            }

                            # Set the message for the backup task
                            if ([string]::IsNullOrEmpty($messages)) {
                                $Message = "The backup completed without errors. " # Ok; success
                            }
                            else {
                                $message = "The backup failed with errors. Please investigate before proceeding. " # Critical; failure
                            }

                            # Set the alert and message update for the backup task based on the age of the backup
                            if ($backupAge -ge 3) {
                                $alert = "RED" # Critical; >= 3 days
                                $messageBackupAge = "Backup is more than 3 days old." # Set the alert message
                            }
                            elseif ($backupAge -gt 1) {
                                $alert = "YELLOW" # Warning; > 1 days
                                $messageBackupAge = "Backup is more than 1 days old." # Set the alert message
                            }
                            else {
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
                            }
                            else {
                                $customObject += $elementObject
                            }  

                            $outputObject += $customObject # Add the custom object to the output object

                            # Return the structured data to the console or format using HTML CSS Styles
                            if ($PsBoundParameters.ContainsKey('html')) { 
                                if ($outputObject.Count -eq 0) {
                                    $addNoIssues = $true 
                                }
                                if ($addNoIssues) {
                                    $outputObject = $outputObject | Sort-Object Component, Resource, Element | ConvertTo-Html -Fragment -PreContent '<a id="infra-backups"></a><h3>Backup Status</h3>' -PostContent '<p>No Issues Found</p>' 
                                }
                                else {
                                    $outputObject = $outputObject | Sort-Object Component, Resource, Element | ConvertTo-Html -Fragment -PreContent '<a id="infra-backups"></a><h3>Backup Status</h3>' -As Table
                                }
                                $outputObject = Convert-CssClass -htmldata $outputObject
                                $outputObject
                            }
                            else {
                                $outputObject | Sort-Object Component, Resource, Element
                            }
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
        Request-DatastoreStorageCapacity -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
        This example will check datastore on all vCenter Servers managed by SDDC Manager instance sfo-vcf01.sfo.rainpole.io.
    #>
    
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomain', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html
    )
        
    # Define thresholds Green < Yellow < Red
    $greenThreshold = 80
    $redThreshold = 90
    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $customObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey("allDomains")) {
                    $allVcenters = Get-VCFvCenter
                    $vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT
                    foreach ($vcenter in $allVcenters) {
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
                                    switch ($usage) {
                                        { $_ -le $greenThreshold } {
                                            # Green if $usage is up to $greenThreshold
                                            $alert = 'GREEN'
                                            $message = "Used space is less than $greenThreshold%. "
                                        }
                                        { $_ -ge $redThreshold } {
                                            # Red if $usage is equal or above $redThreshold
                                            $alert = 'RED'
                                            $message = "Used space is above $redThreshold%. Please reclaim space on the datastore."
                                        }
                                        Default {
                                            # Yellow if above two are not matched
                                            $alert = 'YELLOW'
                                            $message = "Used space is between $greenThreshold% and $redThreshold%. Please consider reclaiming some space on the datastore."
                                        }
                                    }
                                    # Populate data into the object
                                    # Skip population of object if "failureOnly" is selected and alert is "GREEN"
                                    if (($PsBoundParameters.ContainsKey("failureOnly")) -and ($alert -eq 'GREEN')) { continue }
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
                                # Disconnect from the vCenter server
                                Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                            }
                        }
                    }
                }
                else {
                    # Run checks on specific domain only
                    $vcenter = (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $workloadDomain }).vcenters
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
                                switch ($usage) {
                                    { $_ -le $greenThreshold } {
                                        # Green if $usage is up to $greenThreshold
                                        $alert = 'GREEN'
                                        $message = "Used space is less than $greenThreshold%."
                                    }
                                    { $_ -ge $redThreshold } {
                                        # Red if $usage is equal or above $redThreshold
                                        $alert = 'RED'
                                        $message = "Used space is above $redThreshold%. Please reclaim space on the datastore."
                                    }
                                    Default {
                                        # Yellow if above two are not matched
                                        $alert = 'YELLOW'
                                        $message = "Used space is between $greenThreshold% and $redThreshold%. Please consider reclaiming some space on the datastore."
                                    }
                                }
                                # Populate data into the object
                                # Skip population of object if "failureOnly" is selected and alert is "GREEN"
                                if (($PsBoundParameters.ContainsKey("failureOnly")) -and ($alert -eq 'GREEN')) { continue }
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
                            # Disconnect from the vCenter server
                            Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                        }
                    }
                    #}
                }
                # Sort the output FQDN then Datastore Name
                $customObject = $customObject | Sort-Object 'vCenter Server', 'Datastore Type', 'Datastore Name'

                # Return the structured data to the console or format using HTML CSS Styles
                if ($PsBoundParameters.ContainsKey('html')) { 
                    if ($customObject.Count -eq 0) {
                        $customObject = $customObject | ConvertTo-Html -Fragment -PreContent '<a id="storage-datastore"></a><h3>Datastore Space Usage Report</h3>' -PostContent "<p>No Issues Found</p>" 
                    } else {
                        $customObject = $customObject | ConvertTo-Html -Fragment -PreContent '<a id="storage-datastore"></a><h3>Datastore Space Usage Report</h3>' -As Table
                    }
                    $customObject = Convert-CssClass -htmldata $customObject
                }
                # Return $customObject in HTML or plain format
                $customObject | Sort-Object 'vCenter Server', 'Datastore Type', 'Datastore Name'
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
        Checks the disk usage in a vCenter Server instance.

        .DESCRIPTION
        The Request-VcenterStorageHealth cmdlets checks the disk space usage on vCenter Server. The cmdlet 
        connects to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Gathers the details for each vCenter Server
        - Collects information for the disk usage
        - Checks disk usage against thresholds and outputs the results

        .EXAMPLE
        Request-VcenterStorageHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will check the disk usage for all vCenter Server instances managed by SDDC Manager.

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
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT)) {
                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            # Define DF command for vCenter Server
                            $command = 'df -h | grep -e "^/" | grep -v "/dev/loop"'
                            if ($PsBoundParameters.ContainsKey("allDomains")) { 
                                $allVcenters = Get-VCFvCenter
                                foreach ($vcenter in $allVcenters) {
                                    # Compose needed variables
                                    $reportTitle = "<a id=`"storage-vcenter-$($vcenter.fqdn.Split('.')[0])`"></a><h4>Disk Health for vCenter Server: $($vcenter.fqdn)</h4>"
                                    $rootPass = (Get-VCFCredential | Where-Object { $_.credentialType -eq "SSH" -and $_.resource.resourceName -eq $vcenter.fqdn }).password

                                    # Get information from vCenter Server
                                    $dfOutput = Invoke-VMScript -VM ($vcenter.fqdn.Split(".")[0]) -ScriptText $command -GuestUser root -GuestPassword $rootPass -Server $vcfVcenterDetails.fqdn

                                    # Check if we got the information for disk usage and return error if not
                                    if (!$dfOutput) {
                                        if ($PsBoundParameters.ContainsKey("html")) {
                                            ConvertTo-Html -Fragment -PreContent $reportTitle -PostContent "<p>Something went wrong while running the command '$command' on '$($vcenter.fqdn)'. Please check the PowerShell console for more details.</p>"
                                        }
                                        else {
                                            Write-Output "Something went wrong while running the command '$command' on '$($vcenter.fqdn)'. Please check the PowerShell console for more details."
                                        }
                                        continue
                                    }

                                    # Compose command for Format-DfStorageHealth function
                                    if (($PsBoundParameters.ContainsKey("html")) -and ($PsBoundParameters.ContainsKey("failureOnly"))) { 
                                        Format-DfStorageHealth -reportTitle $reportTitle -dfOutput $dfOutput -html -failureOnly
                                    }
                                    elseif ($PsBoundParameters.ContainsKey("html")) {
                                        Format-DfStorageHealth -reportTitle $reportTitle -dfOutput $dfOutput -html
                                    }
                                    elseif ($PsBoundParameters.ContainsKey("failureOnly")) {
                                        Format-DfStorageHealth -reportTitle $reportTitle -dfOutput $dfOutput -failureOnly
                                    }
                                    else {
                                        Format-DfStorageHealth -reportTitle $reportTitle -dfOutput $dfOutput
                                    }
                                }
                            }
                            else {
                                
                                # Compose needed variables
                                $vcenter = (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $workloadDomain }).vcenters
                                $rootPass = (Get-VCFCredential | Where-Object { $_.credentialType -eq "SSH" -and $_.resource.resourceName -eq $vcenter.fqdn }).password
                                $reportTitle = "<a id=`"storage-vcenter-$($vcenter.fqdn.Split('.')[0])`"></a><h4>Disk Health for vCenter Server: $($vcenter.fqdn)</h4>"

                                # Get information from VC
                                $dfOutput = Invoke-VMScript -VM ($vcenter.fqdn.Split(".")[0]) -ScriptText $command -GuestUser root -GuestPassword $rootPass -Server $vcfVcenterDetails.fqdn

                                # Check if we got the information for disk usage and return error if not
                                if (!$dfOutput) {
                                    if ($PsBoundParameters.ContainsKey("html")) {
                                        ConvertTo-Html -Fragment -PreContent $reportTitle -PostContent "<p>Something went wrong while running the command '$command' on '$($vcenter.fqdn)'. Please check the PowerShell console for more details.</p>"
                                    }
                                    else {
                                        Write-Output "Something went wrong while running the command '$command' on '$($vcenter.fqdn)'. Please check the PowerShell console for more details."
                                    }
                                    continue
                                }

                                # Compose command for Format-DfStorageHealth function
                                if (($PsBoundParameters.ContainsKey("html")) -and ($PsBoundParameters.ContainsKey("failureOnly"))) { 
                                    Format-DfStorageHealth -reportTitle $reportTitle -dfOutput $dfOutput -html -failureOnly
                                }
                                elseif ($PsBoundParameters.ContainsKey("html")) {
                                    Format-DfStorageHealth -reportTitle $reportTitle -dfOutput $dfOutput -html
                                }
                                elseif ($PsBoundParameters.ContainsKey("failureOnly")) {
                                    Format-DfStorageHealth -reportTitle $reportTitle -dfOutput $dfOutput -failureOnly
                                }
                                else {
                                    Format-DfStorageHealth -reportTitle $reportTitle -dfOutput $dfOutput
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
Export-ModuleMember -Function Request-VcenterStorageHealth

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
        Request-SddcManagerStorageHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -rootPass VMw@re1!
        This example checks the hard disk space in the SDDC Manager appliance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$rootPass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )
    
    Try {
        # Define some variables
        $reportTitle = "<h4>Disk Health for SDDC Manager: $server</h4>"
        $command = 'df -h | grep -e "^/" | grep -v "/dev/loop"'

        # Get information from SDDC Manager and format it
        $dfOutput = Invoke-SddcCommand -server $server -user $user -pass $pass -rootPass $rootPass -command $command

        # Check if we got the information for disk usage and return error if not
        if (!$dfOutput) {
            if ($PsBoundParameters.ContainsKey("html")) {
                $returnValue = ConvertTo-Html -Fragment -PreContent $reportTitle -PostContent "<p>Something went wrong while running the command: '$command' on $server. Please check the PowerShell console for more details.</p>"
            }
            return $returnValue
        }

        # Compose command for Format-DfStorageHealth function
        if (($PsBoundParameters.ContainsKey("html")) -and ($PsBoundParameters.ContainsKey("failureOnly"))) { 
            Format-DfStorageHealth -reportTitle $reportTitle -dfOutput $dfOutput -html -failureOnly
        }
        elseif ($PsBoundParameters.ContainsKey("html")) {
            Format-DfStorageHealth -reportTitle $reportTitle -dfOutput $dfOutput -html
        }
        elseif ($PsBoundParameters.ContainsKey("failureOnly")) {
            Format-DfStorageHealth -reportTitle $reportTitle -dfOutput $dfOutput -failureOnly
        } else {
            Format-DfStorageHealth -reportTitle $reportTitle -dfOutput $dfOutput
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
        The Request-EsxiStorageCapacity cmdlets checks the disk space usage on ESXi hosts. The cmdlet 
        connects to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Gathers the details for each ESXi host
        - Collects information for the disk usage
        - Checks disk usage against thresholds and outputs the results

        .EXAMPLE
        Request-EsxiStorageCapacity -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will check the disk usage for all ESXi hosts managed by SDDC Manager.

        .EXAMPLE
        Request-EsxiStorageCapacity -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will check disk usage for ESXi hosts managed by SDDC Manager for a single workload domain.

        .EXAMPLE
        Request-EsxiStorageCapacity -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -failureOnly
        This example will check the disk usage for all ESXi hosts managed by SDDC Manager but only reports issues.
    #>

    # TODO: Refactor to Request-EsxiStorageCapacity to remove Posh-SSH dependency.

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        # Define DF command for ESXi
        $command = 'df -h | grep -e "^VMFS-L\|^vfat"'

        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                            
                if ($PsBoundParameters.ContainsKey("allDomains")) { 
                    $allESXis = Get-VCFHost
                    foreach ($esxi in $allESXis) {
                        # Compose needed variables
                        $workloadDomain = (Get-VCFWorkloadDomain -id ((Get-VCFHost -fqdn $esxi.fqdn).domain.id)).name 
                        $reportTitle = "<a id=`"storage-esxi-$workloadDomain`"></a><h4>Disk Health for ESXi Host '$($esxi.fqdn)'. Workload Domain: $workloadDomain</h4>"
                        $esxiUser = (Get-VCFCredential | Where-Object { $_.credentialType -eq "SSH" -and $_.accountType -eq "USER" -and $_.resource.resourceName -eq $esxi.fqdn }).username
                        $esxiUserPass = (Get-VCFCredential | Where-Object { $_.credentialType -eq "SSH" -and $_.accountType -eq "USER" -and $_.resource.resourceName -eq $esxi.fqdn }).password
                        $password = ConvertTo-SecureString $esxiUserPass -AsPlainText -Force
                        $credential = New-Object System.Management.Automation.PSCredential ($esxiUser, $password)
                        # TODO: Explore the possibility to get this information from API and remove Posh-SSH and SSH enabled on ESXi dependencies.
                        $session = New-SSHSession -ComputerName $esxi.fqdn -Credential $credential -Force -WarningAction SilentlyContinue
                        if ($session) { 
                            $commandOutput = Invoke-SSHCommand -Index $session.SessionId -Command $command
                            # Remove session once command is run
                            Remove-SSHSession -Index $session.SessionId | Out-Null
                        }
                        else {
                            # Print error message if connection was not successful and continue to the next ESXi host.
                            ConvertTo-Html -Fragment -PreContent $reportTitle -PostContent "<p>Could not open SSH connection to ESXi host '$($esxi.fqdn)'. Please check the PowerShell console for more details.</p>"
                            continue
                        }
                                    
                        # Format output to be suitable for next function - Format-DfStorageHealth
                        $dfOutput = ($commandOutput.Output -split ', ').Trim()

                        # Compose command for Format-DfStorageHealth function
                        if (($PsBoundParameters.ContainsKey("html")) -and ($PsBoundParameters.ContainsKey("failureOnly"))) { 
                            Format-DfStorageHealth -reportTitle $reportTitle -dfOutput $dfOutput -html -failureOnly
                        }
                        elseif ($PsBoundParameters.ContainsKey("html")) {
                            Format-DfStorageHealth -reportTitle $reportTitle -dfOutput $dfOutput -html
                        }
                        elseif ($PsBoundParameters.ContainsKey("failureOnly")) {
                            Format-DfStorageHealth -reportTitle $reportTitle -dfOutput $dfOutput -failureOnly
                        }
                        else {
                            Format-DfStorageHealth -reportTitle $reportTitle -dfOutput $dfOutput
                        }
                    }
                }
                else {
                    $domainId = (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $workloadDomain }).id
                    $domainESXis = (Get-VCFHost | Where-Object { $_.domain.id -eq $domainId })
                    foreach ($esxi in $domainESXis) {
                        # Compose needed variables
                        $workloadDomain = (Get-VCFWorkloadDomain -id ((Get-VCFHost -fqdn $esxi.fqdn).domain.id)).name 
                        $reportTitle = "<a id=`"storage-esxi-$workloadDomain`"></a><h4>Disk Health for ESXi Host '$($esxi.fqdn)'. Workload Domain: $workloadDomain</h4>"
                        $esxiUser = (Get-VCFCredential | Where-Object { $_.credentialType -eq "SSH" -and $_.accountType -eq "USER" -and $_.resource.resourceName -eq $esxi.fqdn }).username
                        $esxiUserPass = (Get-VCFCredential | Where-Object { $_.credentialType -eq "SSH" -and $_.accountType -eq "USER" -and $_.resource.resourceName -eq $esxi.fqdn }).password
                        $password = ConvertTo-SecureString $esxiUserPass -AsPlainText -Force
                        $credential = New-Object System.Management.Automation.PSCredential ($esxiUser, $password)
                        $session = New-SSHSession -ComputerName $esxi.fqdn -Credential $credential -Force -WarningAction SilentlyContinue
                        if ($session) { 
                            $commandOutput = Invoke-SSHCommand -Index $session.SessionId -Command $command
                            # Remove session once command is run
                            Remove-SSHSession -Index $session.SessionId | Out-Null
                        }
                        else {
                            # Print error message if connection was not successful and continue to the next ESXi host.
                            ConvertTo-Html -Fragment -PreContent $reportTitle -PostContent "<p>Could not open SSH connection to ESXi host '$($esxi.fqdn)'. Please check the PowerShell console for more details.</p>"
                            continue
                        }
                                    
                        # Format output to be suitable for next function - Format-DfStorageHealth
                        $dfOutput = ($commandOutput.Output -split ', ').Trim()

                        # Compose command for Format-DfStorageHealth function
                        if (($PsBoundParameters.ContainsKey("html")) -and ($PsBoundParameters.ContainsKey("failureOnly"))) { 
                            Format-DfStorageHealth -reportTitle $reportTitle -dfOutput $dfOutput -html -failureOnly
                        }
                        elseif ($PsBoundParameters.ContainsKey("html")) {
                            Format-DfStorageHealth -reportTitle $reportTitle -dfOutput $dfOutput -html
                        }
                        elseif ($PsBoundParameters.ContainsKey("failureOnly")) {
                            Format-DfStorageHealth -reportTitle $reportTitle -dfOutput $dfOutput -failureOnly
                        }
                        else {
                            Format-DfStorageHealth -reportTitle $reportTitle -dfOutput $dfOutput
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
        - Performs checks on the local OS users and outputs the results

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
        [Parameter (ParameterSetName = 'Specific-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
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
            $allConnectivityObject = $allConnectivityObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="general-connectivity"></a><h3>Connectivity Health Status</h3>' -PostContent '<p>No Issues Found</p>' 
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
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
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

                # Return the structured data to the console or format using HTML CSS Styles
                if ($PsBoundParameters.ContainsKey("html")) { 
                    $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>vCenter Server Connectivity Health Status</h3>" -As Table
                    $customObject = Convert-CssClass -htmldata $customObject
                    $customObject
                } else {
                    $customObject | Sort-Object Component, Resource 
                }
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
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
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
                            if (Test-NsxtAuthentication -server $node.fqdn -user $vcfNsxDetails.adminUser -pass $vcfNsxDetails.adminPass) {
                                $alert = "GREEN"
                                $message = "API Connection check successful!"
                            }
                            else {
                                $alert = "RED"
                                $message = "API Connection check failed!"
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
                        if (Test-NsxtAuthentication -server $node.fqdn -user $vcfNsxDetails.adminUser -pass $vcfNsxDetails.adminPass) {
                            $alert = "GREEN"
                            $message = "API Connection check successful!"
                        }
                        else {
                            $alert = "RED"
                            $message = "API Connection check failed!"
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

                # Return the structured data to the console or format using HTML CSS Styles
                if ($PsBoundParameters.ContainsKey("html")) { 
                    $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>NSX Manager Connectivity Health Status</h3>" -As Table
                    $customObject = Convert-CssClass -htmldata $customObject
                    $customObject
                } else {
                    $customObject | Sort-Object Component, Resource 
                }
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-NsxtAuthentication

Function Request-NsxtTier0BgpStatus {
    <#
        .SYNOPSIS
        Returns the BGP status for all Tier-0 gateways managed by the NSX Manager cluster.

        .DESCRIPTION
        The Request-NsxtTier0BgpStatus cmdlet returns the BGP status for all Tier-0 gateways managed by the NSX Manager
        cluster. The cmdlet connects to the NSX-T Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the NSX-T Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Gathers the details for the NSX Manager cluster
        - Collects the BGP status for all Tier-0s managed by the NSX Manager cluster

        .EXAMPLE
        Request-NsxtTier0BgpStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return the BGP status for all Tier-0 gateways managed by the NSX Manager cluster that is managed by SDDC Manager for a workload domain.

        .EXAMPLE
        Request-NsxtTier0BgpStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
        This example will return the BGP status for all Tier-0 gateways managed by the NSX Manager cluster that is managed by SDDC Manager for a workload domain but only reports issues.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfNsxDetails = Get-NsxtServerDetail -fqdn $server -username $user -password $pass -domain $domain)) {
                    if (Test-NSXTConnection -server $vcfNsxDetails.fqdn) {
                        if (Test-NSXTAuthentication -server $vcfNsxDetails.fqdn -user $vcfNsxDetails.adminUser -pass $vcfNsxDetails.adminPass) {
                            $customObject = New-Object System.Collections.ArrayList

                            $component = "BGP"
                            
                            $tier0s = Get-NsxtTier0Gateway

                            foreach ($tier0 in $tier0s) {

                                $bgpStatus = Get-NsxtTier0BgpStatus -id $tier0.id | Where-Object {$_.type -eq 'USER'}

                                foreach ($element in $bgpStatus) {

                                    if ($element.connection_state -eq 'ESTABLISHED') {  
                                        $alert = "GREEN"
                                        $message = "BGP is established."
                                    }
                                    else {
                                        $alert = "RED"
                                        $message = "BGP is not established. Please check the configuration."
                                    }

                                    # TODO: Add warnings based on length of established time (e.g., flapping) or low prefix counts which may indicate a problem.
                                    # TODO: Another option is to use Get-NsxtAlert to get the status for BGP and then use that to determine the alert state and message versus the current logic.

                                    $elementObject = New-Object -TypeName psobject
                                    # NSX Tier-0 BGP Status Properties

                                    # TODO: Capture the local ASN alongside the remote ASN. 

                                    $elementObject | Add-Member -NotePropertyName 'NSX Manager' -NotePropertyValue $vcfNsxDetails.fqdn
                                    $elementObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain
                                    $elementObject | Add-Member -NotePropertyName 'Tier-0 ID' -NotePropertyValue $tier0.id
                                    $elementObject | Add-Member -NotePropertyName 'Connection' -NotePropertyValue $element.connection_state
                                    $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
                                    $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $message
                                    $elementObject | Add-Member -NotePropertyName 'Source Address' -NotePropertyValue $element.source_address
                                    $elementObject | Add-Member -NotePropertyName 'Neighbor Address' -NotePropertyValue $element.neighbor_address
                                    $elementObject | Add-Member -NotePropertyName 'Remote ASN' -NotePropertyValue $element.remote_as_number
                                    $elementObject | Add-Member -NotePropertyName 'Hold' -NotePropertyValue $element.hold_time
                                    $elementObject | Add-Member -NotePropertyName 'Keep Alive ' -NotePropertyValue $element.keep_alive_interval
                                    $elementObject | Add-Member -NotePropertyName 'Established Time (sec)' -NotePropertyValue $element.time_since_established
                                    $elementObject | Add-Member -NotePropertyName 'Total In Prefix' -NotePropertyValue $element.total_in_prefix_count
                                    $elementObject | Add-Member -NotePropertyName 'Total Out Prefix' -NotePropertyValue $element.total_out_prefix_count
                                    
                                    if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                        if ($element.connection_state -ne 'ESTABLISHED') {
                                            $customObject += $elementObject | Sort-Object 'NSX Manager', 'Domain', 'Tier-0 ID', 'Source Address'
                                        }
                                    }
                                    else {
                                        $customObject += $elementObject | Sort-Object 'NSX Manager', 'Domain', 'Tier-0 ID', 'Source Address'
                                    }  
                                }
                            }

                            $outputObject += $customObject # Add the custom object to the output object

                            # Return the structured data to the console or format using HTML CSS Styles
                            if ($PsBoundParameters.ContainsKey('html')) { 
                                if ($outputObject.Count -eq 0) {
                                    $addNoIssues = $true 
                                }
                                if ($addNoIssues) {
                                    $outputObject = $outputObject | Sort-Object 'NSX Manager', 'Domain', 'Tier-0 ID', 'Source Address' | ConvertTo-Html -Fragment -PreContent '<a id="nsx-t0-bgp"></a><h3>NSX Tier-0 Gateway BGP Status</h3>' -PostContent '<p>No Issues Found</p>' 
                                }
                                else {
                                    $outputObject = $outputObject | Sort-Object 'NSX Manager', 'Domain', 'Tier-0 ID', 'Source Address' | ConvertTo-Html -Fragment -PreContent '<a id="nsx-t0-bgp"></a><h3>NSX Tier-0 Gateway BGP Status</h3>' -As Table
                                }
                                $outputObject = Convert-CssClass -htmldata $outputObject
                                $outputObject
                            }
                            else {
                                $outputObject | Sort-Object 'NSX Manager', 'Domain', 'Tier-0 ID', 'Source Address'
                            }                    
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
                    $allAlertObject = $allAlertObject | Sort-Object Component, Resource, Domain | ConvertTo-Html -Fragment -PreContent '<a id="alert-esxi"></a><h3>ESXi Host Alert</h3>' -PostContent '<p>No Issues Found</p>' 
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
                    $allAlertObject = $allAlertObject | Sort-Object Component, Resource, Domain | ConvertTo-Html -Fragment -PreContent '<a id="alert-nsx"></a><h3>NSX-T Data Center Alert</h3>' -PostContent '<p>No Issues Found</p>' 
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
                    $allAlertObject = $allAlertObject | Sort-Object Component, Resource, Domain | ConvertTo-Html -Fragment -PreContent '<a id="alert-vcenter"></a><h3>vCenter Server Alert</h3>' -PostContent '<p>No Issues Found</p>' 
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
                    $allAlertObject = $allAlertObject | Sort-Object Component, Resource, Domain | ConvertTo-Html -Fragment -PreContent '<a id="alert-vsan"></a><h3>vSAN Alert</h3>' -PostContent '<p>No Issues Found</p>' 
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
                    if (Test-NSXTAuthentication -server $vcfNsxDetails.fqdn -user $vcfNsxDetails.adminUser -pass $vcfNsxDetails.adminPass) {
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
                            #$elementObject | Add-Member -NotePropertyName 'Last Reported Time' -NotePropertyValue $element.last_reported_time # Set the last_reported_time in [Long]
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

Function Publish-EsxiPasswordPolicy {
    <#
        .SYNOPSIS
        Publish password policy for ESXi hosts in a vCenter Server instance managed by SDDC Manager.

        .DESCRIPTION
        The Publish-EsxiPasswordPolicy cmdlet returns password policy from ESXi hosts managed by SDDC Manager.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Server instance
        - Validates the authentication to vCenter Server with credentials from SDDC Manager
        - Collects password policy from all ESXi hosts in vCenter Server instance

        .EXAMPLE
        Publish-EsxiPasswordPolicy -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will return password policy from all ESXi hosts in vCenter Server managed by SDDC Manager for a all workload domains.

        .EXAMPLE
        Publish-EsxiPasswordPolicy -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
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
                $allWorkloadDomains = Get-VCFWorkloadDomain
                $allEsxiPolicyObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('allDomains')) {
                    foreach ($domain in $allWorkloadDomains ) {
                        $esxiPolicy = Request-EsxiPasswordPolicy -server $server -user $user -pass $pass -domain $domain.name; $allEsxiPolicyObject += $esxiPolicy
                    }
                }
                else {
                    $esxiPolicy = Request-EsxiPasswordPolicy -server $server -user $user -pass $pass -domain $workloadDomain; $allEsxiPolicyObject += $esxiPolicy
                }
                $allEsxiPolicyObject = $allEsxiPolicyObject | Sort-Object Component, Resource, Domain | ConvertTo-Html -Fragment -PreContent '<a id="policy-esxi"></a><h3>ESXi Password Policy</h3>' -As Table
                $allEsxiPolicyObject = Convert-CssClass -htmldata $allEsxiPolicyObject
                $allEsxiPolicyObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-EsxiPasswordPolicy

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

        .EXAMPLE
        Request-EsxiPasswordPolicy -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -html
        This example will return the Password Policy configuration for ESXi hosts managed by SDDC Manager for a workload domain and output in HTML
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html
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
                                        $passwordPolicy = Get-VMHost -name $esxiHost | Where-Object { $_.ConnectionState -eq "Connected" } | Get-AdvancedSetting | Where-Object { $_.Name -eq "Security.PasswordQualityControl" }
                                        if ($passwordPolicy -and $passwordExpire) {
                                            $passwordPolicy.Value | Select-String -Pattern "^retry=(\d+)\s+min=(.+),(.+),(.+),(.+),(.+)" | Foreach-Object {$PasswdPolicyRetryValue, $PasswdPolicyMinValue1, $PasswdPolicyMinValue2, $PasswdPolicyMinValue3, $PasswdPolicyMinValue4, $PasswdPolicyMinValue5 = $_.Matches[0].Groups[1..6].Value}
                                        }
                                        $hostPasswordPolicyObject = New-Object -TypeName psobject
                                        $hostPasswordPolicyObject | Add-Member -notepropertyname "Cluster" -notepropertyvalue $cluster
                                        $hostPasswordPolicyObject | Add-Member -notepropertyname "ESXi FQDN" -notepropertyvalue $esxiHost.Name
                                        $hostPasswordPolicyObject | Add-Member -notepropertyname "Expiry (days)" -notepropertyvalue (Get-VMHost -name $esxiHost | Where-Object { $_.ConnectionState -eq "Connected" } | Get-AdvancedSetting | Where-Object { $_.Name -eq "Security.PasswordMaxDays" }).Value
                                        $hostPasswordPolicyObject | Add-Member -notepropertyname "Password History" -notepropertyvalue (Get-VMHost -name $esxiHost | Where-Object { $_.ConnectionState -eq "Connected" } | Get-AdvancedSetting | Where-Object { $_.Name -eq "Security.PasswordHistory" }).Value
                                        $hostPasswordPolicyObject | Add-Member -notepropertyname "Failed Login Attempts" -notepropertyvalue (Get-VMHost -name $esxiHost | Where-Object { $_.ConnectionState -eq "Connected" } | Get-AdvancedSetting | Where-Object { $_.Name -eq "Security.AccountLockFailures" }).Value
                                        $hostPasswordPolicyObject | Add-Member -notepropertyname "Lockout Time (sec)" -notepropertyvalue (Get-VMHost -name $esxiHost | Where-Object { $_.ConnectionState -eq "Connected" } | Get-AdvancedSetting | Where-Object { $_.Name -eq "Security.AccountUnlockTime" }).Value                                        
                                        $hostPasswordPolicyObject | Add-Member -notepropertyname "Password Retry (max)" -notepropertyvalue $PasswdPolicyRetryValue
                                        $hostPasswordPolicyObject | Add-Member -notepropertyname "Password Policy" -notepropertyvalue ($PasswdPolicyMinValue1 + "," + $PasswdPolicyMinValue2 + "," + $PasswdPolicyMinValue3 + "," + $PasswdPolicyMinValue4)
                                        $hostPasswordPolicyObject | Add-Member -notepropertyname "Password Length" -notepropertyvalue $PasswdPolicyMinValue5
                                        $esxiPasswordPolicyObject += $hostPasswordPolicyObject
                                    }
                                    $clusterObject += $esxiPasswordPolicyObject
                                }
                                Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null

                                # Return the structured data to the console or format using HTML CSS Styles
                                if ($PsBoundParameters.ContainsKey("html")) { 
                                    $clusterObject = $clusterObject | Sort-Object Cluster, 'ESXi FQDN' | ConvertTo-Html -Fragment -PreContent '<a id="policy-esxi"></a><h3>ESXi Password Policy</h3>' -As Table
                                    $clusterObject = Convert-CssClass -htmldata $clusterObject
                                } else {
                                    $clusterObject | Sort-Object Cluster, 'ESXi FQDN'
                                }
                                $clusterObject
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
            @{ Name=("PowerValidatedSolutions"); Version=("1.5.0")}
            @{ Name=("VMware.PowerCLI"); Version=("12.4.1")}
            @{ Name=("VMware.vSphere.SsoAdmin"); Version=("1.3.7")}
            @{ Name=("Posh-SSH"); Version=("3.0.1")} # TODO: Refactor to Request-EsxiStorageCapacity to remove Posh-SSH dependency.
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
        [Parameter (Mandatory = $true)] [ValidateSet("health","alert","config","upgrade","policy")] [String]$reportType
    )

    $filetimeStamp = Get-Date -Format "MM-dd-yyyy_hh_mm_ss"
    if ($reportType -eq "health") { $Global:reportFolder = $path + '\HealthReports\' }
    if ($reportType -eq "alert") { $Global:reportFolder = $path + '\AlertReports\' }
    if ($reportType -eq "config") { $Global:reportFolder = $path + '\ConfigReports\' }
    if ($reportType -eq "upgrade") { $Global:reportFolder = $path + '\UpgradeReports\' }
    if ($reportType -eq "policy") { $Global:reportFolder = $path + '\PolicyReports\' }
    if (!(Test-Path -Path $reportFolder)) {
        New-Item -Path $reportFolder -ItemType "directory" | Out-Null
    }
    Copy-Item -Path "./*.css" -Destination $path -Force -Confirm:$False
    Copy-Item -Path "./*.svg" -Destination $path -Force -Confirm:$False
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
    # Define the default Clarity Cascading Style Sheets (CSS) for the HTML report Header
    $clarityCssHeader = '
        <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
        <html xmlns="http://www.w3.org/1999/xhtml">
        
        <head>
            <link href="../clr-ui.css" rel="stylesheet" />
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
        [Parameter (Mandatory = $true)] [ValidateSet("health","alert","config","upgrade","policy")] [String]$reportType
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
                <a class="nav-link nav-icon" href="#policy-vcenter">vCenter Server</a>
                <a class="nav-link nav-icon" href="#policy-esxi">ESXi</a>
                <a class="nav-link nav-icon" href="#policy-vsan">vSAN</a>
                <a class="nav-link nav-icon" href="#policy-nsx">NSX-T Data Center</a>
            </section>
            </nav>
                <div class="content-area">
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

Function PercentCalc {
    Param (
        [Parameter (Mandatory = $true)] [Int]$InputNum1,
        [Parameter (Mandatory = $true)] [Int]$InputNum2
    )
    
    $InputNum1 / $InputNum2*100
}

Function Format-DfStorageHealth {
    <#
		.SYNOPSIS
        Formats output from 'fd -h' command and set alerts based on thresholds.

        .DESCRIPTION
        The Format-DfStorageHealth cmdlet formats and returns output from 'df -h' in html or plain text

        .EXAMPLE
        Format-DfStorageHealth -reportTitle '<h3>SDDC Manager Disk Health Status</h3>' -dfOutput $dfOutput -html -failureOnly -greenThreshold 20 -redThreshold 40
        This example returns only failures (Alert is not GREEN), produces html report with title '<h3>SDDC Manager Disk Health Status</h3>' and overwrites the default thresholds
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$reportTitle,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] $dfOutput,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
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
            switch ($usage) {
                { $_ -le $greenThreshold } {
                    # Green if $usage is up to $greenThreshold
                    $alert = 'GREEN'
                    $message = "Used space is less than $greenThreshold%."
                }
                { $_ -ge $redThreshold } {
                    # Red if $usage is equal or above $redThreshold
                    $alert = 'RED'
                    $message = "Used space is above $redThreshold%. Please reclaim space on the partition."
                    # TODO: Find how to display the message in html on multiple rows (Add <br> with the right escape chars)
                    # In order to display usage, you could run as root in SDDC Manager 'du -Sh <mount-point> | sort -rh | head -10' "
                    # As an alternative you could run PowerCLI commandlet:
                    # 'Invoke-SddcCommand -server <SDDC_Manager_FQDN> -user <administrator@vsphere.local> -pass <administrator@vsphere.local_password> -rootPass <SDDC_Manager_RootPassword> -command "du -Sh <mount-point> | sort -rh | head -10" '
                }
                Default {
                    # Yellow if above two are not matched
                    # TODO: Same as above - add hints on new lines }
                    $alert = 'YELLOW'
                    $message = "Used space is between $greenThreshold% and $redThreshold%. Please consider reclaiming some space on the partition."
                }
            }
            
            # Skip population of object if "failureOnly" is selected and alert is "GREEN"
            if (($PsBoundParameters.ContainsKey("failureOnly")) -and ($alert -eq 'GREEN')) { continue }

            # TODO Add logic/information (new field "instance/FQDN") to $customObject in case -html is not specified.
            # In this way the returned information will be easier to handle for following processing of the returned object
            
            $userObject = New-Object -TypeName psobject
            $userObject | Add-Member -notepropertyname 'Filesystem' -notepropertyvalue $partition.Split(" ")[0]
            $userObject | Add-Member -notepropertyname 'Size' -notepropertyvalue $partition.Split(" ")[1]
            $userObject | Add-Member -notepropertyname 'Available' -notepropertyvalue $partition.Split(" ")[2]
            $userObject | Add-Member -notepropertyname 'Used %' -notepropertyvalue $partition.Split(" ")[4]
            $userObject | Add-Member -notepropertyname 'Mounted on' -notepropertyvalue $partition.Split(" ")[5]
            $userObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $alert
            $userObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $message
            $customObject += $userObject # Creating collection to work with afterwords
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) { 
            if ($customObject.Count -eq 0) {
                $customObject = $customObject | ConvertTo-Html -Fragment -PreContent $reportTitle -PostContent "<p>No Issues Found</p>" 
            }
            else {
                $customObject = $customObject | ConvertTo-Html -Fragment -PreContent $reportTitle -As Table
            }
            $customObject = Convert-CssClass -htmldata $customObject
        }
        $customObject # Return $customObject in HTML or pain format
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
            $expiryDays = [math]::Ceiling((([DateTime]$endDate) - (Get-Date)).TotalDays)

            # Set the alet for the local user account based on the expiry date
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
        Debug-CatchWriter -object $_
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
        Debug-CatchWriter -object $_
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
        Debug-CatchWriter -object $_
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
        }
        else {
            Write-Warning "No backup schedules configured."
        }
    }
    Catch {
        Debug-CatchWriter -object $_
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
        }
        else {
            $backupJobAPI.list() # Return all backup jobs
        }
    }
    Catch {
        Debug-CatchWriter -object $_
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

    $backupJobAPI = Get-CisService 'com.vmware.appliance.recovery.backup.job' # Get the backup job API from the vSphere Automation API
    foreach ($id in $jobID) {
        $backupJobAPI.get("$id") | Select-Object id, progress, state, start_time, end_time, messages
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
        if (Get-VM -Name $vm) {
            $snapshot = Get-VM $vm | Get-Snapshot | Select-Object -Property Name, Created, isCurrent # Get the snapshot details
            # Return the snapshot details
            foreach ($snapshot in $snapshot) {
                $snapshotDays = [math]::Ceiling(((Get-Date) - ([DateTime]$snapshot.Created)).TotalDays) # Calculate the number of days since the snapshot was created
                
                # Set the alert color based on the age of the snapshot
                if ($snapshotDays -ge 3) {
                    $alert = 'RED' # Critical: >= 3 days
                    $message = "The snapshot is greater than or equal to 3 days old."
                }
                if ($snapshotDays -gt 1) {
                    $alert = 'YELLOW' # Warning: > 1 days
                    $message = "The snapshot is greater than 1 day old."
                }
                else {
                    $alert = 'GREEN' # OK: <= 1 days
                    $message = "The snapshot is less than 1 day old."
                }
                # Create a new PSObject to hold the results
                $snapshotObject = New-Object -TypeName psobject
                # Add the snapshot details to the PSObject
                $snapshotObject | Add-Member -NotePropertyName 'Virtual Machine' -NotePropertyValue $vm
                $snapshotObject | Add-Member -NotePropertyName 'Snapshot Name' -NotePropertyValue $snapshot.Name
                $snapshotObject | Add-Member -NotePropertyName 'Created' -NotePropertyValue $snapshot.Created
                $snapshotObject | Add-Member -NotePropertyName 'Current' -NotePropertyValue $snapshot.isCurrent
                $snapshotObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
                $snapshotObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $message
                $snapshotObject | Sort-Object 'Virtual Machine', 'Created', 'Current'
            }
        }
        else {
            Write-Error "Unable to locate virtual machine ($name) in the vCenter Server inventory."
        }

    }
    Catch {
        Debug-CatchWriter -object $_
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
        if (Get-VM -Name $vm) {
            $snapshotConsolidation = (Get-View -ViewType VirtualMachine -Filter @{'Name' = $vm }).Runtime.ConsolidationNeeded # Get the consolidation status
            $snapshotCount = (Get-VM $vm | Get-Snapshot).Count # Get the number of snapshots
            # Set the alert and message based on the consolidation status
            if ($consolidation -eq $true) {
                $alert = 'RED' # Critical: Consolidation needed
                $message = "Consolidation is required. "
            }
            else {
                $alert = 'GREEN' # OK: Consolidation not needed
                $message = "Consolidation is not required. "
            }

            if ($snapshotCount -gt 1) {
                $messageAppend = "Use 'Get-SnapshotStatus -vm $vm' to review the status of each snapshot."
            }

            $message += $messageAppend # Combine the alert message

            # Create a new PSObject to hold the results
            $outputObject = New-Object -TypeName psobject
            # Add the snapshot details to the PSObject
            $outputObject = New-Object -TypeName psobject
            $outputObject | Add-Member -NotePropertyName 'Virtual Machine' -NotePropertyValue $vm
            $outputObject | Add-Member -NotePropertyName 'Snapshots' -NotePropertyValue $snapshotCount
            $outputObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
            $outputObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue "$message"
            $outputObject
        }
        else {
            Write-Error "Unable to locate virtual machine ($name) in the vCenter Server inventory."
        }
    }
    Catch {
        Debug-CatchWriter -object $_
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

=======
=======
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
        Debug-CatchWriter -object $_
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
        Debug-CatchWriter -object $_
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
        Get-NsxtTier0BgpStatus -id sfo-w01-nsx01.sfo.rainpole.io
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
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Get-NsxtTier0BgpStatus

##############################  End Supporting Functions ###############################
########################################################################################
