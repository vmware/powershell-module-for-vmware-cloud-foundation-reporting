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
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
}

if ($PSEdition -eq 'Desktop') {
    # Allow communication with self-signed certificates when using Windows PowerShell
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

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

        if (Test-VCFConnection -server $sddcManagerFqdn) {
            if (Test-VCFAuthentication -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass) {
                $defaultReport = Start-CreateReportDirectory -path $reportPath -sddcManagerFqdn $sddcManagerFqdn -reportType health # Setup Report Location and Report File
                if (!(Test-Path -Path $reportPath)) {Write-Warning "Unable to locate report path $reportPath, enter a valid path and try again"; Write-Host ""; Break }
                if ($PsBoundParameters.ContainsKey("allDomains")) {
                    $reportname = $defaultReport.Split('.')[0] + "-" + $sddcManagerFqdn.Split(".")[0] + ".htm"
                    $workflowMessage = "VMware Cloud Foundation instance ($sddcManagerFqdn)"
                } else {
                    $reportname = $defaultReport.Split('.')[0] + "-" + $workloadDomain + ".htm"
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

                # Generating the ESXi Connection Health Data Using PowerShell Request Functions
                Write-LogMessage -type INFO -Message "Generating the ESXi Connection Health Data report for $workflowMessage."
                if ($PsBoundParameters.ContainsKey('allDomains') -and $PsBoundParameters.ContainsKey('failureOnly')) {
                    $esxiConnectionHtml = Publish-EsxiConnectionHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains -failureOnly
                }
                elseif ($PsBoundParameters.ContainsKey('allDomains')) {
                    $esxiConnectionHtml = Publish-EsxiConnectionHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains
                }
                if ($PsBoundParameters.ContainsKey('workloadDomain') -and $PsBoundParameters.ContainsKey('failureOnly')) {
                    $esxiConnectionHtml = Publish-EsxiConnectionHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain -failureOnly
                }
                elseif ($PsBoundParameters.ContainsKey('workloadDomain')) {
                    $esxiConnectionHtml = Publish-EsxiConnectionHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
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

                # Generating the Free Pool Health Data Using PowerShell Request Functions
                Write-LogMessage -type INFO -Message "Generating the SDDC Manager Free Pool Health for $workflowMessage."
                if ($PsBoundParameters.ContainsKey("failureOnly")) {
                    $freePoolHtml = Publish-SddcManagerFreePool -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -failureOnly
                } else {
                    $freePoolHtml = Publish-SddcManagerFreePool -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass
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

                # Generating the NSX Transport Node Tunnel Health Data Using PowerShell Request Functions
                Write-LogMessage -type INFO -Message "Generating the NSX Transport Node Tunnel Report for $workflowMessage."
                if ($PsBoundParameters.ContainsKey('allDomains') -and $PsBoundParameters.ContainsKey('failureOnly')) {
                    $nsxTransportNodeTunnelHtml = Publish-NsxtTransportNodeTunnelStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains -failureOnly
                }
                elseif ($PsBoundParameters.ContainsKey('allDomains')) {
                    $nsxTransportNodeTunnelHtml = Publish-NsxtTransportNodeTunnelStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains
                }
                if ($PsBoundParameters.ContainsKey('workloadDomain') -and $PsBoundParameters.ContainsKey('failureOnly')) {
                    $nsxTransportNodeTunnelHtml = Publish-NsxtTransportNodeTunnelStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain -failureOnly
                }
                elseif ($PsBoundParameters.ContainsKey('workloadDomain')) {
                    $nsxTransportNodeTunnelHtml = Publish-NsxtTransportNodeTunnelStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
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

                # Generating the Virtual Machines with Connected CD-ROM Health Data Using PowerShell Request Functions
                Write-LogMessage -type INFO -Message "Generating the Virtual Machines with Connected CD-ROM Report for $workflowMessage."
                if ($PsBoundParameters.ContainsKey('allDomains')) {
                    $vmConnectedCdromHtml = Publish-VmConnectedCdrom -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains
                } else {
                    $vmConnectedCdromHtml = Publish-VmConnectedCdrom -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
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
                $reportData += $esxiConnectionHtml
                $reportData += $freePoolHtml
                $reportData += $vsanHtml
                $reportData += $vsanPolicyHtml
                $reportData += $nsxtHtml
                $reportData += $nsxtEdgeClusterHtml
                $reportData += $nsxtEdgeNodeHtml
                $reportData += $nsxTransportNodeHtml
                $reportData += $nsxTransportNodeTunnelHtml
                $reportData += $nsxTier0BgpHtml
                $reportData += $storageCapacityHealthHtml
                $reportData += $vmConnectedCdromHtml

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
                if ($PSEdition -eq "Core" -and ($PSVersionTable.OS).Split(' ')[0] -ne "Linux") {
                    Invoke-Item $reportName
                } elseif ($PSEdition -eq "Desktop") {
                    Invoke-Item $reportName
                }
            }
        }
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

        if (Test-VCFConnection -server $sddcManagerFqdn) {
            if (Test-VCFAuthentication -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass) {
                $defaultReport = Start-CreateReportDirectory -path $reportPath -sddcManagerFqdn $sddcManagerFqdn -reportType alert # Setup Report Location and Report File
                if (!(Test-Path -Path $reportPath)) {Write-Warning "Unable to locate report path $reportPath, enter a valid path and try again"; Write-Host ""; Break }
                if ($PsBoundParameters.ContainsKey("allDomains")) {
                    $reportname = $defaultReport.Split('.')[0] + "-" + $sddcManagerFqdn.Split(".")[0] + ".htm"
                    $workflowMessage = "VMware Cloud Foundation instance ($sddcManagerFqdn)"
                } else {
                    $reportname = $defaultReport.Split('.')[0] + "-" + $workloadDomain + ".htm"
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
                if ($PSEdition -eq "Core" -and ($PSVersionTable.OS).Split(' ')[0] -ne "Linux") {
                    Invoke-Item $reportName
                } elseif ($PSEdition -eq "Desktop") {
                    Invoke-Item $reportName
                }
            }
        }
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

        if (Test-VCFConnection -server $sddcManagerFqdn) {
            if (Test-VCFAuthentication -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass) {
                $defaultReport = Start-CreateReportDirectory -path $reportPath -sddcManagerFqdn $sddcManagerFqdn -reportType config # Setup Report Location and Report File
                if (!(Test-Path -Path $reportPath)) {Write-Warning "Unable to locate report path $reportPath, enter a valid path and try again"; Write-Host ""; Break }
                if ($PsBoundParameters.ContainsKey("allDomains")) {
                    $reportname = $defaultReport.Split('.')[0] + "-" + $sddcManagerFqdn.Split(".")[0] + ".htm"
                    $workflowMessage = "VMware Cloud Foundation instance ($sddcManagerFqdn)"
                } else {
                    $reportname = $defaultReport.Split('.')[0] + "-" + $workloadDomain + ".htm"
                    $workflowMessage = "Workload Domain ($workloadDomain)"
                }
                Start-SetupLogFile -Path $reportPath -ScriptName $MyInvocation.MyCommand.Name # Setup Log Location and Log File
                Write-LogMessage -Type INFO -Message "Starting the Process of Creating a Configuration Report for $workflowMessage." -Colour Yellow
                Write-LogMessage -Type INFO -Message "Setting up the log file to path $logfile."
                Write-LogMessage -Type INFO -Message "Setting up report folder and report $reportName."

                # Collecting Cluster Configuration Using PowerShell Functions
                Write-LogMessage -Type INFO -Message "Generating the Cluster Configuration for $workflowMessage."
                if ($PsBoundParameters.ContainsKey("allDomains")) {
                    $clusterConfigHtml = Publish-ClusterConfiguration -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains
                } else {
                    $clusterConfigHtml = Publish-ClusterConfiguration -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
                }

                # Collecting Cluster DRS Rules Using PowerShell Functions
                Write-LogMessage -Type INFO -Message "Generating the DRS Rule Configuration for $workflowMessage."
                if ($PsBoundParameters.ContainsKey("allDomains")) {
                    $clusterDrsRuleHtml = Publish-ClusterDrsRule -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains
                } else {
                    $clusterDrsRuleHtml = Publish-ClusterDrsRule -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
                }

                # Collecting Resource Pool Details  Using PowerShell Functions
                Write-LogMessage -Type INFO -Message "Generating the Resouce Pool Configuration for $workflowMessage."
                if ($PsBoundParameters.ContainsKey("allDomains")) {
                    $resourcePoolsHtml = Publish-ResourcePool -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains
                } else {
                    $resourcePoolsHtml = Publish-ResourcePool -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
                }

                # Collecting VM Overrides Using PowerShell Functions
                Write-LogMessage -Type INFO -Message "Generating the VM Override Configuration for $workflowMessage."
                if ($PsBoundParameters.ContainsKey("allDomains")) {
                    $vmOverridesHtml = Publish-VmOverride -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains
                } else {
                    $vmOverridesHtml = Publish-VmOverride -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
                }

                # Collecting Virtual Networking Using PowerShell Functions
                Write-LogMessage -Type INFO -Message "Generating the Virtual Networking Configuration for $workflowMessage."
                if ($PsBoundParameters.ContainsKey("allDomains")) {
                    $vritualNetworkHtml = Publish-VirtualNetwork -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains
                } else {
                    $vritualNetworkHtml = Publish-VirtualNetwork -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
                }

                # Collecting ESXi Security Configuration Using PowerShell Functions
                Write-LogMessage -Type INFO -Message "Generating the ESXi Security Configuration for $workflowMessage."
                if ($PsBoundParameters.ContainsKey("allDomains")) {
                    $esxiSecuritykHtml = Publish-EsxiSecurityConfiguration -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains
                } else {
                    $esxiSecuritykHtml = Publish-EsxiSecurityConfiguration -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
                }

                # Combine all information gathered into a single HTML report
                if ($PsBoundParameters.ContainsKey("allDomains")) {
                    $reportData = "<h1>SDDC Manager: $sddcManagerFqdn</h1>"
                } else {
                    $reportData = "<h1>Workload Domain: $workloadDomain</h1>"
                }
                $reportData += $clusterConfigHtml
                $reportData += $clusterDrsRuleHtml
                $reportData += $resourcePoolsHtml
                $reportData += $vmOverridesHtml
                $reportData += $vritualNetworkHtml
                $reportData += $esxiSecuritykHtml

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
                if ($PSEdition -eq "Core" -and ($PSVersionTable.OS).Split(' ')[0] -ne "Linux") {
                    Invoke-Item $reportName
                } elseif ($PSEdition -eq "Desktop") {
                    Invoke-Item $reportName
                }
            }
        }
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

        if (Test-VCFConnection -server $sddcManagerFqdn) {
            if (Test-VCFAuthentication -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass) {
                $defaultReport = Start-CreateReportDirectory -path $reportPath -sddcManagerFqdn $sddcManagerFqdn -reportType upgrade # Setup Report Location and Report File
                if (!(Test-Path -Path $reportPath)) {Write-Warning "Unable to locate report path $reportPath, enter a valid path and try again"; Write-Host ""; Break }
                $reportname = $defaultReport.Split('.')[0] + "-" + $workloadDomain + ".htm"
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
                if ($PSEdition -eq "Core" -and ($PSVersionTable.OS).Split(' ')[0] -ne "Linux") {
                    Invoke-Item $reportName
                } elseif ($PSEdition -eq "Desktop") {
                    Invoke-Item $reportName
                }
            }
        }
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

        if (Test-VCFConnection -server $sddcManagerFqdn) {
            if (Test-VCFAuthentication -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass) {
                $defaultReport = Start-CreateReportDirectory -path $reportPath -sddcManagerFqdn $sddcManagerFqdn -reportType policy # Setup Report Location and Report File
                if (!(Test-Path -Path $reportPath)) {Write-Warning "Unable to locate report path $reportPath, enter a valid path and try again"; Write-Host ""; Break }
                if ($PsBoundParameters.ContainsKey("allDomains")) {
                    $reportname = $defaultReport.Split('.')[0] + "-" + $sddcManagerFqdn.Split(".")[0] + ".htm"
                    $workflowMessage = "VMware Cloud Foundation instance ($sddcManagerFqdn)"
                } else {
                    $reportname = $defaultReport.Split('.')[0] + "-" + $workloadDomain + ".htm"
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
                if ($PSEdition -eq "Core" -and ($PSVersionTable.OS).Split(' ')[0] -ne "Linux") {
                    Invoke-Item $reportName
                } elseif ($PSEdition -eq "Desktop") {
                    Invoke-Item $reportName
                }
            }
        }
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

        .EXAMPLE
        Invoke-VcfOverviewReport -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser admin@local -sddcManagerPass VMw@re1!VMw@re1! -reportPath F:\Reporting -anonymized
        This example generates the system overview report for a VMware Cloud Foundation instance, but will anonymize the output.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerFqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerUser,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerPass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$reportPath,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$darkMode,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$anonymized
    )

    Try {
        Clear-Host; Write-Host ""

        if (Test-VCFConnection -server $sddcManagerFqdn) {
            if (Test-VCFAuthentication -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass) {
                $defaultReport = Start-CreateReportDirectory -path $reportPath -sddcManagerFqdn $sddcManagerFqdn -reportType overview # Setup Report Location and Report File
                if (!(Test-Path -Path $reportPath)) {Write-Warning "Unable to locate report path $reportPath, enter a valid path and try again"; Write-Host ""; Break }
                $reportname = $defaultReport.Split('.')[0] + "-" + $sddcManagerFqdn.Split(".")[0] + ".htm"
                $workflowMessage = "VMware Cloud Foundation instance ($sddcManagerFqdn)"
                Start-SetupLogFile -Path $reportPath -ScriptName $MyInvocation.MyCommand.Name # Setup Log Location and Log File
                Write-LogMessage -Type INFO -Message "Starting the Process of Creating a System Overview Report for $workflowMessage." -Colour Yellow
                Write-LogMessage -Type INFO -Message "Setting up the log file to path $logfile."
                Write-LogMessage -Type INFO -Message "Setting up report folder and report $reportName."

                if ($PsBoundParameters.ContainsKey("anonymized")) {
                    Write-LogMessage -Type INFO -Message "Generating Anonymized System Overview Report for $workflowMessage."
                    $vcfOverviewHtml = Publish-VcfSystemOverview -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -anonymized
                } else {
                    Write-LogMessage -Type INFO -Message "Generating System Overview Report for $workflowMessage."
                    $vcfOverviewHtml = Publish-VcfSystemOverview -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass
                }

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
                if ($PSEdition -eq "Core" -and ($PSVersionTable.OS).Split(' ')[0] -ne "Linux") {
                    Invoke-Item $reportName
                } elseif ($PSEdition -eq "Desktop") {
                    Invoke-Item $reportName
                }
            }
        }
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
            if ($PSEdition -eq "Core" -and ($PSVersionTable.OS).Split(' ')[0] -eq "Linux") {
                $reportDestination = ($reportDestination = ($reportPath + "\" + $server.Split(".")[0] + "-all-health-results.json")).split('\') -join '/' | Split-Path -NoQualifier
            } else {
                $reportDestination = ($reportPath + "\" + $server.Split(".")[0] + "-all-health-results.json")
            }
        } elseif ($PsBoundParameters.ContainsKey("workloadDomain")) {
            $command = "/opt/vmware/sddc-support/sos --health-check --skip-known-host-check --json-output-dir /tmp/jsons --domain-name " + $workloadDomain
            if ($PSEdition -eq "Core" -and ($PSVersionTable.OS).Split(' ')[0] -eq "Linux") {
                $reportDestination = ($reportDestination = ($reportPath + "\" + $workloadDomain + "-all-health-results.json")).split('\') -join '/' | Split-Path -NoQualifier
            } else {
                $reportDestination = ($reportPath + "\" + $workloadDomain + "-all-health-results.json")
            }
        }
        Invoke-SddcCommand -server $server -user $user -pass $pass -vmUser root -vmPass $rootPass -command $command | Out-Null
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
        } else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }

        $customObject = New-Object System.Collections.ArrayList
        $jsonInputData = $targetContent.'Certificates'.'Certificate Status' # Extract Data from the provided SOS JSON
        if (($jsonInputData | Measure-Object).Count -lt 1) {
            Write-Warning 'Certificate Status data not found in the JSON file: SKIPPED'
        } else {
            $jsonInputData.PSObject.Properties.Remove('ESXI')
            foreach ($component in $jsonInputData.PsObject.Properties.Value) {
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
                    } else {
                        $customObject += $elementObject
                    }
                }
            }
            $outputObject += $customObject
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey('html')) {
            if (($jsonInputData | Measure-Object).Count -gt 0) {
                if ($outputObject.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="security-certificate"></a><h3>Certificate Health Status</h3>' -PostContent '<p>No issues found.</p>'
                } else {
                    $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="security-certificate"></a><h3>Certificate Health Status</h3>' -As Table
                }
                $outputObject = Convert-CssClass -htmlData $outputObject
            } else {
                $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="infra-ntp"></a><h3>NTP Health Status</h3>' -PostContent '<p><strong>WARNING</strong>: Certificate Status data not found.</p>' -As Table
            }
            $outputObject
        } else {
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
        $jsonInputCheck = $targetContent.Connectivity.'Connectivity Status' # Extract Data from the provided SOS JSON
        if (($jsonInputCheck | Measure-Object).Count -lt 1) {
            Write-Warning 'Connectivity Status data not found in the JSON file: SKIPPED'
        } else {  

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
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey('html')) {
            if (($jsonInputData | Measure-Object).Count -gt 0) {
                if ($outputObject.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="general-connectivity"></a><h3>Connectivity Health Status</h3>' -PostContent '<p>No issues found.</p>'
                } else {
                    $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="general-connectivity"></a><h3>Connectivity Health Status</h3>' -As Table
                }
                $customObject = Convert-CssClass -htmldata $customObject
            } else {
                $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="general-connectivity"></a><h3>Connectivity Health Status</h3>' -PostContent '<p><strong>WARNING</strong>: Connectivity Status data not found.</p>' -As Table
            }
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
        $jsonForwardLookupInput = $targetContent.'DNS lookup Status'.'Forward lookup Status' # Extract Data from the provided SOS JSON
        if (($jsonForwardLookupInput | Measure-Object).Count -lt 1) {
            Write-Warning 'Forward Lookup Status not found in the JSON file: SKIPPED'
        } else {
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                $allForwardLookupObject = Read-JsonElement -inputData $jsonForwardLookupInput -failureOnly # Call Function to Structure the Data for Report Output
            } else {
                $allForwardLookupObject = Read-JsonElement -inputData $jsonForwardLookupInput # Call Function to Structure the Data for Report Output
            }
        }

        # Reverse Lookup Health Status
        $allReverseLookupObject = New-Object System.Collections.ArrayList
        $jsonReverseLookupInput = $targetContent.'DNS lookup Status'.'Reverse lookup Status' # Extract Data from the provided SOS JSON
        if (($jsonReverseLookupInput | Measure-Object).Count -lt 1) {
            Write-Warning 'Reverse Lookup Status not found in the JSON file: SKIPPED'
        } else {
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                $allReverseLookupObject = Read-JsonElement -inputData $jsonReverseLookupInput -failureOnly # Call Function to Structure the Data for Report Output
            } else {
                $allReverseLookupObject = Read-JsonElement -inputData $jsonReverseLookupInput # Call Function to Structure the Data for Report Output
            }
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) {
            if (($jsonForwardLookupInput | Measure-Object).Count -gt 0) {
                if ($allForwardLookupObject.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $allForwardLookupObject = $allForwardLookupObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="infra-dns-forward"></a><h3>DNS Forward Lookup Health Status</h3>' -PostContent '<p>No issues found.</p>'
                } else {
                    $allForwardLookupObject = $allForwardLookupObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="infra-dns-forward"></a><h3>DNS Forward Lookup Health Status</h3>' -As Table
                }
                $allForwardLookupObject = Convert-CssClass -htmldata $allForwardLookupObject
            } else {
                $allForwardLookupObject = $allForwardLookupObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="infra-dns-forward"></a><h3>DNS Forward Lookup Health Status</h3>' -PostContent '<p><strong>WARNING</strong>: Forward Lookup Status data not found.</p>' -As Table
            }
            $allForwardLookupObject

            if (($jsonReverseLookupInput | Measure-Object).Count -gt 0) {
                if ($allReverseLookupObject.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $allReverseLookupObject = $allReverseLookupObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="infra-dns-reverse"></a><h3>DNS Reverse Lookup Health Status</h3>' -PostContent '<p>No issues found.</p>'
                } else {
                    $allReverseLookupObject = $allReverseLookupObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="infra-dns-reverse"></a><h3>DNS Reverse Lookup Health Status</h3>' -As Table
                }
                $allReverseLookupObject = Convert-CssClass -htmldata $allReverseLookupObject
            } else {
                $allReverseLookupObject = $allReverseLookupObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="infra-dns-reverse"></a><h3>DNS Reverse Lookup Health Status</h3>' -PostContent '<p><strong>WARNING</strong>: Reverse Lookup Status data not found.</p>' -As Table
            }
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

        $jsonGeneralCheck = $targetContent.General # Extract Data from the provided SOS JSON
        if (($jsonGeneralCheck | Measure-Object).Count -lt 1) {
            Write-Warning 'General data not found in the JSON file: SKIPPED'
        } else {
            # ESXi Core Dump Status
            $allCoreDumpObject = New-Object System.Collections.ArrayList
            $jsonInputData = $targetContent.General.'ESXi Core Dump Status' # Extract Data from the provided SOS JSON
            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                $allCoreDumpObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
            }
            else {
                $allCoreDumpObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Rep
            }
        }

        $jsonComputeCheck = $targetContent.Compute # Extract Data from the provided SOS JSON
        if (($jsonComputeCheck | Measure-Object).Count -lt 1) {
            Write-Warning 'Compute data not found in the JSON file: SKIPPED'
        } else {  
            # ESXi Overall Health Status
            $jsonInputData = $targetContent.Compute.'ESXi Overall Health' # Extract Data from the provided SOS JSON
            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                $allOverallHealthObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
            }
            else {
                $allOverallHealthObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
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
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey('html')) {
            if (($jsonGeneralCheck | Measure-Object).Count -gt 0) {
                if ($allCoreDumpObject.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $allCoreDumpObject = $allCoreDumpObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-coredump"></a><h3>ESXi Core Dump Health Status</h3>' -PostContent '<p>No issues found.</p>'
                } else {
                    $allCoreDumpObject = $allCoreDumpObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-coredump"></a><h3>ESXi Core Dump Health Status</h3>' -As Table
                }
                $allCoreDumpObject = Convert-CssClass -htmldata $allCoreDumpObject
            } else {
                $allCoreDumpObject = $allCoreDumpObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-coredump"></a><h3>ESXi Core Dump Health Status</h3>' -PostContent '<p><strong>WARNING</strong>: ESXi Core Dump data not found.</p>' -As Table
            }
            $allCoreDumpObject

            if (($jsonComputeCheck | Measure-Object).Count -gt 0) {
                if ($allOverallHealthObject.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $allOverallHealthObject = $allOverallHealthObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-overall"></a><h3>ESXi Overall Health Status</h3>' -PostContent '<p>No issues found.</p>'
                } else {
                    $allOverallHealthObject = $allOverallHealthObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-overall"></a><h3>ESXi Overall Health Status</h3>' -As Table
                }
                $allOverallHealthObject = Convert-CssClass -htmldata $allOverallHealthObject
            } else {
                $allOverallHealthObject = $allOverallHealthObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-overall"></a><h3>ESXi Overall Health Status</h3>' -PostContent '<p><strong>WARNING</strong>: ESXi Overall Health data not found.</p>' -As Table
            }
            $allOverallHealthObject

            if (($jsonComputeCheck | Measure-Object).Count -gt 0) {
                if ($allLicenseObject.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $allLicenseObject = $allLicenseObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-license"></a><h3>ESXi License Health Status</h3>' -PostContent '<p>No issues found.</p>'
                } else {
                    $allLicenseObject = $allLicenseObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-license"></a><h3>ESXi License Health Status</h3>' -As Table
                }
                $allLicenseObject = Convert-CssClass -htmldata $allLicenseObject
            } else {
                $allLicenseObject = $allLicenseObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-license"></a><h3>ESXi License Health Status</h3>' -PostContent '<p><strong>WARNING</strong>: ESXi License data not found.</p>' -As Table
            }
            $allLicenseObject

            if (($jsonComputeCheck | Measure-Object).Count -gt 0) { 
                if ($allDiskObject.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $allDiskObject = $allDiskObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-disk"></a><h3>ESXi Disk Health Status</h3>' -PostContent '<p>No issues found.</p>'
                } else {
                    $allDiskObject = $allDiskObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-disk"></a><h3>ESXi Disk Health Status</h3>' -As Table
                }
                $allDiskObject = Convert-CssClass -htmldata $allDiskObject
            } else {
                $allDiskObject = $allDiskObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="esxi-disk"></a><h3>ESXi Disk Health Status</h3>' -PostContent '<p><strong>WARNING</strong>: ESXi Disk data not found.</p>' -As Table
            }
            $allDiskObject
        }
        else {
            $allCoreDumpObject | Sort-Object Component, Resource
            $allOverallHealthbject | Sort-Object Component, Resource
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
        $jsonInputCheck = $targetContent.General.'NSX Health' # Extract Data from the provided SOS JSON
        if (($jsonInputCheck | Measure-Object).Count -lt 1) {
            Write-Warning 'NSX Health data not found in the JSON file: SKIPPED'
        } else {  

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
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey('html')) {
            if (($jsonInputData | Measure-Object).Count -gt 0) {
                if ($customObject.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $customObject = $customObject | Sort-Object Resource, Component | ConvertTo-Html -Fragment -PreContent '<a id="nsx-local-manager"></a><h3>NSX Manager Health Status</h3>' -PostContent '<p>No issues found.</p>'
                } else {
                    $customObject = $customObject | Sort-Object Resource, Component | ConvertTo-Html -Fragment -PreContent '<a id="nsx-local-manager"></a><h3>NSX Manager Health Status</h3>' -As Table
                }
                $customObject = Convert-CssClass -htmldata $customObject
            } else {
                $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="nsx-local-manager"></a><h3>NSX Manager Health Status</h3>' -PostContent '<p><strong>WARNING</strong>: NSX Health data not found.</p>' -As Table
            }
            $customObject
        } else {
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
        if (($jsonInputData | Measure-Object).Count -lt 1) {
            Write-Warning "NSX Health data for NSX Edges not found in the JSON file: SKIPPED"
        } else {
            $nsxtClusters = Get-VCFNsxtCluster
            foreach ($nsxtVip in $nsxtClusters.vipFqdn) {
                $jsonInputData.PSObject.Properties.Remove($nsxtVip)
            }
            $jsonInputData = $jsonInputData | Where-Object {$_ -ne ""}
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
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey('html')) {
            if (($jsonInputData | Measure-Object).Count -gt 0) {
                if ($customObject.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="nsx-edge"></a><h3>NSX Edge Node Health Status</h3>' -PostContent '<p>No issues found.</p>'
                } else {
                    $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="nsx-edge"></a><h3>NSX Edge Node Health Status</h3>' -As Table
                }
                $customObject = Convert-CssClass -htmldata $customObject
            } else {
                $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="nsx-edge"></a><h3>NSX Edge Node Health Status</h3>' -PostContent '<p><strong>WARNING</strong>: NSX Health data for NSX Edges not found. This warning is safe to ignore if NSX Edges are not managed by SDDC Manager.</p>' -As Table
            }
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
        if (($jsonInputData | Measure-Object).Count -lt 1) {
            Write-Warning "NSX Health data for NSX Edge Cluster not found in the JSON file: SKIPPED"
        }
        else {
            $nsxtEdgeClusters = Get-VCFEdgeCluster
            foreach ($nsxtEdgeNodes in $nsxtEdgeClusters.edgeNodes.hostname) {
                $jsonInputData.PSObject.Properties.Remove($nsxtEdgeNodes)
            }
            if ($null -eq $nsxtEdgeClusters) {
                $nsxtClusters = Get-VCFNsxtCluster
                foreach ($nsxtCluster in $nsxtClusters) {
                    $jsonInputData.PSObject.Properties.Remove($nsxtCluster.vipFqdn)
                }
            }
            $jsonInputData = $jsonInputData | Where-Object {$_ -ne ""}
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
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey('html')) {
            if (($jsonInputData | Measure-Object).Count -gt 0) {
                if ($customObject.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="nsx-edge-cluster"></a><h3>NSX Edge Cluster Health Status</h3>' -PostContent '<p>No issues found.</p>'
                } else {
                    $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="nsx-edge-cluster"></a><h3>NSX Edge Cluster Health Status</h3>' -As Table
                }
                $customObject = Convert-CssClass -htmldata $customObject
            } else {
                $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="nsx-edge-cluster"></a><h3>NSX Edge Cluster Health Status</h3>' -PostContent '<p><strong>WARNING</strong>: NSX Health data for Edge Cluster not found. This warning is safe to ignore if NSX Edges are not managed by SDDC Manager.</p>' -As Table
            }
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
        if (($jsonInputData | Measure-Object).Count -lt 1) {
            Write-Warning 'NTP data not found in the JSON file: SKIPPED'
        } else {
            $jsonInputData.PSObject.Properties.Remove('ESXi HW Time')
            $jsonInputData.PSObject.Properties.Remove('ESXi Time')

            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
            }
            else {
                $outputObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
            }
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) {
            if (($jsonInputData | Measure-Object).Count -gt 0) {
                if ($outputObject.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="infra-ntp"></a><h3>NTP Health Status</h3>' -PostContent '<p>No issues found.</p>'
                } else {
                    $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="infra-ntp"></a><h3>NTP Health Status</h3>' -As Table
                }
                $outputObject = Convert-CssClass -htmldata $outputObject
            } else {
                $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="infra-ntp"></a><h3>NTP Health Status</h3>' -PostContent '<p><strong>WARNING</strong>: NTP data not found.</p>' -As Table
            }
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
        if (($jsonInputData | Measure-Object).Count -lt 1) {
            Write-Warning 'Password Expiry Status not found in the JSON file: SKIPPED'
        } else {
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
            } else {
                $outputObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
            }
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) {
            if (($jsonInputData | Measure-Object).Count -gt 0) {
                if ($outputObject.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="security-password"></a><h3>Password Expiry Health Status</h3>' -PostContent '<p>No issues found.</p>'
                } else {
                    $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="security-password"></a><h3>Password Expiry Health Status</h3>' -As Table
                }
                $outputObject = Convert-CssClass -htmldata $outputObject
            } else {
                $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="security-password"></a><h3>Password Expiry Health Status</h3>' -PostContent '<p><strong>WARNING</strong>: Password Expiry Status data not found.</p>' -As Table
            }
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
        if (($inputData | Measure-Object).Count -lt 1) {
            Write-Warning 'Services data not found in the JSON file: SKIPPED'
        } else {
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
        }

        if ($PsBoundParameters.ContainsKey('html')) {
            if (($inputData | Measure-Object).Count -gt 0) {
                if ($outputObject.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="general-service"></a><h3>Service Health Status</h3>' -PostContent '<p>No issues found.</p>'
                } else {
                    $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="general-service"></a><h3>Service Health Status</h3>' -As Table
                }
                $outputObject = Convert-CssClass -htmldata $outputObject
            } else {
                $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="general-service"></a><h3>Service Health Status</h3>' -PostContent '<p><strong>WARNING</strong>: Services data not found.</p>' -As Table
            }
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
        if (($jsonInputData | Measure-Object).Count -lt 1) {
            Write-Warning "vCenter Server Overall Health data not found in the JSON file: SKIPPED"
        } else {
            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                $vcenterOverall = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
            } else {
                $vcenterOverall = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
            }

            # Ring Topology Health
            $ringTopologyHealth = New-Object System.Collections.ArrayList
            $vcfVersion = ((Get-VCFManager).version -Split ('\.\d{1}\-\d{8}')) -split '\s+' -match '\S'
            if ($vcfVersion -eq "4.2.1") {
                $jsonInputData = $targetContent.Connectivity.'Vcenter Ring Topology Status'.'Vcenter Ring Topology Status' # Extract Data from the provided SOS JSON
            } else {
                $jsonInputData = $targetContent.General.'Vcenter Ring Topology Status'.'Vcenter Ring Topology Status' # Extract Data from the provided SOS JSON
            }
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
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) {
            if (($jsonInputData | Measure-Object).Count -gt 0) {
                if ($vcenterOverall.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $vcenterOverall = $vcenterOverall | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="vcenter-overall"></a><h3>vCenter Server Overall Health Status</h3>' -PostContent '<p>No issues found.</p>'
                } else {
                    $vcenterOverall = $vcenterOverall | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="vcenter-overall"></a><h3>vCenter Server Overall Health Status</h3>' -As Table
                }
                $vcenterOverall = Convert-CssClass -htmldata $vcenterOverall
            } else {
                $vcenterOverall = $vcenterOverall | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="vcenter-overall"></a><h3>vCenter Server Overall Health Status</h3>' -PostContent '<p><p><strong>WARNING</strong>: vCenter Server Overall Health data not found.</p>' -As Table
            }
            $vcenterOverall
        } else {
            $vcenterOverall | Sort-Object Component, Resource
        }

        if ($PsBoundParameters.ContainsKey('html')) {
            if (($jsonInputData | Measure-Object).Count -gt 0) {
            if (@($ringTopologyHealth).Count -lt 1) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $ringTopologyHealth = $ringTopologyHealth | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="vcenter-ring-topology"></a><h3>vCenter Server Ring Topology Health Status</h3>' -PostContent '<p>No issues found.</p>'
                } else {
                    $ringTopologyHealth = $ringTopologyHealth | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="vcenter-ring-topology"></a><h3>vCenter Server Ring Topology Health Status</h3>' -As Table
                }
                $ringTopologyHealth = Convert-CssClass -htmldata $ringTopologyHealth
            } else {
                $ringTopologyHealth = $ringTopologyHealth | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="vcenter-ring-topology"></a><h3>vCenter Server Ring Topology Health Status</h3>' -PostContent '<p><strong>WARNING</strong>: vCenter Server Overall Health data not found.</p>' -As Table
            }
        } else {
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
        Formats the vSAN Health data from the SoS JSON output.

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
        $jsonInputCheck = $targetContent.vSAN # Extract Data from the provided SOS JSON
        if (($jsonInputCheck | Measure-Object).Count -lt 1) {
            Write-Warning 'vSAN data not found in the JSON file: SKIPPED'
        } else {  

            # vSAN Cluster Health Status
            $jsonInputData = $targetContent.vSAN.'Cluster vSAN Status' # Extract Data from the provided SOS JSON
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
            } else {
                $outputObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
            }
            $customObject += $outputObject # Adding individual component to main customObject

            # Cluster Disk Status
            $jsonInputData = $targetContent.vSAN.'Cluster Disk Status' # Extract Data from the provided SOS JSON
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
            } else {
                $outputObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
            }
            $customObject += $outputObject # Adding individual component to main customObject

            # Cluster Data Compression Status
            $jsonInputData = $targetContent.vSAN.'Cluster Data Compression Status' # Extract Data from the provided SOS JSON
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
            } else {
                $outputObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
            }
            $customObject += $outputObject # Adding individual component to main customObject

            # Cluster Data Encryption Status
            $jsonInputData = $targetContent.vSAN.'Cluster Data Encryption Status' # Extract Data from the provided SOS JSON
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
            } else {
                $outputObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
            }
            $customObject += $outputObject # Adding individual component to main customObject

            # Cluster Data Deduplication Status
            $jsonInputData = $targetContent.vSAN.'Cluster Data Deduplication Status' # Extract Data from the provided SOS JSON
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
            } else {
                $outputObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
            }
            $customObject += $outputObject # Adding individual component to main customObject

            # Stretched Cluster Status
            $jsonInputData = $targetContent.vSAN.'Stretched Cluster Status' # Extract Data from the provided SOS JSON
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly # Call Function to Structure the Data for Report Output
            } else {
                $outputObject = Read-JsonElement -inputData $jsonInputData # Call Function to Structure the Data for Report Output
            }
            $customObject += $outputObject # Adding individual component to main customObject
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) {
            if (($jsonInputData | Measure-Object).Count -gt 0) {
                if ($customObject.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="vsan-overall"></a><h3>vSAN Overall Health Status</h3>' -PostContent '<p>No issues found.</p>'
                } else {
                    $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="vsan-overall"></a><h3>vSAN Overall Health Status</h3>' -As Table
                }
                $customObject = Convert-CssClass -htmldata $customObject
            } else {
                $customObject = $customObject | ConvertTo-Html -Fragment -PreContent '<a id="vsan-overall"></a><h3>vSAN Overall Health Status</h3>' -PostContent '<p><strong>WARNING</strong>: vSAN data not found.</p>'
            }
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

Function Publish-VsanStoragePolicy {
    <#
        .SYNOPSIS
        Formats the vSAN Storage Policy for virtual machines from the SoS JSON output.

        .DESCRIPTION
        The Publish-VsanStoragePolicy cmdlet formats the vSAN Storage Policy data from the SoS JSON output and
        publishes it as either a standard PowerShell object or an HTML object.

        .EXAMPLE
        Publish-VsanStoragePolicy -json <file-name>
        This example extracts and formats the vSAN Storage Policy data as a PowerShell object from the JSON file.

        .EXAMPLE
        Publish-VsanStoragePolicy -json <file-name> -html
        This example extracts and formats the vSAN Storage Policy data as an HTML object from the JSON file.

        .EXAMPLE
        Publish-VsanStoragePolicy -json <file-name> -failureOnly
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
        if (($jsonInputData | Measure-Object).Count -lt 1) {
            Write-Warning 'vSAN data not found in the JSON file: SKIPPED'
        } else {
            $jsonInputData.PSObject.Properties.Remove('Host vSAN Status')
            $jsonInputData.PSObject.Properties.Remove('Host Disk Status')
            $jsonInputData.PSObject.Properties.Remove('Cluster vSAN Status')
            $jsonInputData.PSObject.Properties.Remove('Cluster Disk Status')
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
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) {
            if (($jsonInputData | Measure-Object).Count -gt 0) {
                if ($outputObject.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $outputObject = $outputObject | Sort-Object Component, 'vCenter Server', Resource | ConvertTo-Html -Fragment -PreContent '<a id="vsan-spbm"></a><h3>vSAN Storage Policy Health Status</h3>' -PostContent '<p>No issues found.</p>'
                } else {
                    $outputObject = $outputObject | Sort-Object Component, 'vCenter Server', Resource | ConvertTo-Html -Fragment -PreContent '<a id="vsan-spbm"></a><h3>vSAN Storage Policy Health Status</h3>' -As Table
                }
            $outputObject = Convert-CssClass -htmldata $outputObject
            }
            else {
                $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<a id="vsan-spbm"></a><h3>vSAN Storage Policy Health Status</h3>' -PostContent '<p><strong>WARNING</strong>: vSAN data not found.</p>' -As Table
            }
            $outputObject
        } else {
            $outputObject | Sort-Object Component, 'vCenter Server', Resource
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-VsanStoragePolicy

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
                        $vcenterBackupStatus = Request-vCenterBackupStatus -server $server -user $user -pass $pass -domain $workloadDomain -failureOnly; $allBackupStatusObject += $vcenterBackupStatus
                        $nsxtManagerBackupStatus = Request-NsxtManagerBackupStatus -server $server -user $user -pass $pass -domain $workloadDomain -failureOnly; $allBackupStatusObject += $nsxtManagerBackupStatus
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
                        $allBackupStatusObject = $allBackupStatusObject | Sort-Object Component, Resource, Element | ConvertTo-Html -Fragment -PreContent '<a id="infra-backup"></a><h3>Backups Status</h3>' -PostContent "<p>No issues found.</p><p>Please verify that each successful file-based backup exists on the destination.</p>"
                    } else {
                        $allBackupStatusObject = $allBackupStatusObject | Sort-Object Component, Resource, Element | ConvertTo-Html -Fragment -PreContent '<a id="infra-backup"></a><h3>Backups Status</h3>' -PostContent "<p>Please verify that each successful file-based backup exists on the destination.</p>" -As Table
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
                    } else {
                        $nsxtTransportNodeStatus = Request-NsxtTransportNodeStatus -server $server -user $user -pass $pass -domain $workloadDomain -failureOnly; $allNsxtTransportNodeStatusObject += $nsxtTransportNodeStatus
                    }
                }
                else {
                    if ($PsBoundParameters.ContainsKey('allDomains')) {
                        foreach ($domain in $allWorkloadDomains ) {
                            $nsxtTransportNodeStatus = Request-NsxtTransportNodeStatus -server $server -user $user -pass $pass -domain $domain.name; $allNsxtTransportNodeStatusObject += $nsxtTransportNodeStatus
                        }
                    } else {
                        $nsxtTransportNodeStatus = Request-NsxtTransportNodeStatus -server $server -user $user -pass $pass -domain $workloadDomain; $allNsxtTransportNodeStatusObject += $nsxtTransportNodeStatus
                    }
                }

                if ($allNsxtTransportNodeStatusObject.Count -eq 0) {
                    $addNoIssues = $true
                }
                if ($addNoIssues) {
                    $allNsxtTransportNodeStatusObject = $allNsxtTransportNodeStatusObject | Sort-Object Domain, Resource, Element | ConvertTo-Html -Fragment -PreContent '<a id="nsx-tn"></a><h3>NSX Transport Node Status</h3>' -PostContent '<p>No issues found.</p>'
                } else {
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

Function Publish-NsxtTransportNodeTunnelStatus {
    <#
		.SYNOPSIS
        Request and publish the status of NSX transport node tunnels.

        .DESCRIPTION
        The Publish-NsxtTransportNodeStatus cmdlet checks the status NSX transport node tunnels and prepares the data
        to be published to an HTML report. The cmdlet connects to SDDC Manager using the -server, -user, and password
        values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Performs checks on the NSX transport node tunnel status and outputs the results

        .EXAMPLE
        Publish-NsxtTransportNodeTunnelStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will publish the status of all NSX transport node tunnels in a VMware Cloud Foundation instance.

        .EXAMPLE
        Publish-NsxtTransportNodeTunnelStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -failureOnly
        This example will publish thestatus of all NSX transport node tunnels in a VMware Cloud Foundation instance but only reports issues.

        .EXAMPLE
        Publish-NsxtTransportNodeTunnelStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will publish the BGP status for the NSX transport node tunnels in a VMware Cloud Foundation instance for a workload domain named sfo-w01.
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
                $allNsxtTransportNodeTunnelStatusObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                    if ($PsBoundParameters.ContainsKey('allDomains')) {
                        foreach ($domain in $allWorkloadDomains ) {
                            $nsxtTransportNodeTunnelStatus = Request-NsxtTransportNodeTunnelStatus -server $server -user $user -pass $pass -domain $domain.name -failureOnly; $allNsxtTransportNodeTunnelStatusObject += $nsxtTransportNodeTunnelStatus
                        }
                    } else {
                        $nsxtTransportNodeTunnelStatus = Request-NsxtTransportNodeTunnelStatus -server $server -user $user -pass $pass -domain $workloadDomain -failureOnly; $allNsxtTransportNodeTunnelStatusObject += $nsxtTransportNodeTunnelStatus
                    }
                } else {
                    if ($PsBoundParameters.ContainsKey('allDomains')) {
                        foreach ($domain in $allWorkloadDomains ) {
                            $nsxtTransportNodeTunnelStatus = Request-NsxtTransportNodeTunnelStatus -server $server -user $user -pass $pass -domain $domain.name; $allNsxtTransportNodeTunnelStatusObject += $nsxtTransportNodeTunnelStatus
                        }
                    } else {
                        $nsxtTransportNodeTunnelStatus = Request-NsxtTransportNodeTunnelStatus -server $server -user $user -pass $pass -domain $workloadDomain; $allNsxtTransportNodeTunnelStatusObject += $nsxtTransportNodeTunnelStatus
                    }
                }

                if ($allNsxtTransportNodeTunnelStatusObject.Count -eq 0) { $addNoIssues = $true }
                if ($allNsxtTransportNodeTunnelStatusObject.Count -ne 0) {
                    if ($addNoIssues) {
                        $allNsxtTransportNodeTunnelStatusObject = $allNsxtTransportNodeTunnelStatusObject | Sort-Object Domain, Resource, Element | ConvertTo-Html -Fragment -PreContent '<a id="nsx-tn-tunnel"></a><h3>NSX Transport Node Tunnel Status</h3>' -PostContent '<p>No issues found.</p>'
                    } else {
                        $allNsxtTransportNodeTunnelStatusObject = $allNsxtTransportNodeTunnelStatusObject | Sort-Object Domain, Resource, Element  | ConvertTo-Html -Fragment -PreContent '<a id="nsx-tn-tunnel"></a><h3>NSX Transport Node Tunnel Status</h3>' -As Table
                    }
                    $allNsxtTransportNodeTunnelStatusObject = Convert-CssClass -htmlData $allNsxtTransportNodeTunnelStatusObject
                } else {
                    $allNsxtTransportNodeTunnelStatusObject = $allNsxtTransportNodeTunnelStatusObject | ConvertTo-Html -Fragment -PreContent '<a id="nsx-tn-tunnel"></a><h3>NSX Transport Node Tunnel Status</h3>' -PostContent '<p>No NSX Transport Node Tunnels found.</p>'
                }
                $allNsxtTransportNodeTunnelStatusObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-NsxtTransportNodeTunnelStatus

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
                        $nsxtTier0BgpStatus = Request-NsxtTier0BgpStatus -server $server -user $user -pass $pass -domain $workloadDomain -failureOnly; $allNsxtTier0BgpStatusObject += $nsxtTier0BgpStatus
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

                if ($allNsxtTier0BgpStatusObject.Count -eq 0) { $addNoIssues = $true }
                if ($nsxtTier0BgpStatus.Count -gt 0) {
                    if ($addNoIssues) {
                        $allNsxtTier0BgpStatusObject = $allNsxtTier0BgpStatusObject | Sort-Object 'NSX Manager', 'Domain', 'Tier-0 ID', 'Source Address' | ConvertTo-Html -Fragment -PreContent '<a id="nsx-t0-bgp"></a><h3>NSX Tier-0 Gateway BGP Status</h3>' -PostContent '<p>No issues found.</p>'
                    } else {
                        $allNsxtTier0BgpStatusObject = $allNsxtTier0BgpStatusObject | Sort-Object 'NSX Manager', 'Domain', 'Tier-0 ID', 'Source Address' | ConvertTo-Html -Fragment -PreContent '<a id="nsx-t0-bgp"></a><h3>NSX Tier-0 Gateway BGP Status</h3>' -As Table
                    }
                    $allNsxtTier0BgpStatusObject = Convert-CssClass -htmldata $allNsxtTier0BgpStatusObject
                } else {
                    $allNsxtTier0BgpStatusObject = $allNsxtTier0BgpStatusObject | ConvertTo-Html -Fragment -PreContent '<a id="nsx-t0-bgp"></a><h3>NSX Tier-0 Gateway BGP Status</h3>' -PostContent '<p>No BGP configuration found on NSX Tier-0 Gateway(s).</p>' -As Table
                }
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
                $allWorkloadDomains = Get-VCFWorkloadDomain
                $singleWorkloadDomain = Get-VCFWorkloadDomain | Where-Object {$_.name -eq $workloadDomain}
                if ($PsBoundParameters.ContainsKey('failureOnly')) {
                    if ($PsBoundParameters.ContainsKey('allDomains')) {
                        $sddcManagerSnapshotStatus = Request-SddcManagerSnapshotStatus -server $server -user $user -pass $pass -failureOnly; $allSnapshotStatusObject += $sddcManagerSnapshotStatus
                        foreach ($domain in $allWorkloadDomains ) {
                            $vcenterSnapshotStatus = Request-VcenterSnapshotStatus -server $server -user $user -pass $pass -domain $domain.name -failureOnly; $allSnapshotStatusObject += $vcenterSnapshotStatus
                            $nsxtEdgeSnapshotStatus = Request-NsxtEdgeSnapshotStatus -server $server -user $user -pass $pass -domain $domain.name -failureOnly; $allSnapshotStatusObject += $nsxtEdgeSnapshotStatus
                        }
                    } else {
                        if ($singleWorkloadDomain.type -eq "MANAGEMENT") {
                            $sddcManagerSnapshotStatus = Request-SddcManagerSnapshotStatus -server $server -user $user -pass $pass -failureOnly; $allSnapshotStatusObject += $sddcManagerSnapshotStatus
                        }
                        $vcenterSnapshotStatus = Request-VcenterSnapshotStatus -server $server -user $user -pass $pass -domain $workloadDomain -failureOnly; $allSnapshotStatusObject += $vcenterSnapshotStatus
                        $nsxtEdgeSnapshotStatus = Request-NsxtEdgeSnapshotStatus -server $server -user $user -pass $pass -domain $workloadDomain -failureOnly; $allSnapshotStatusObject += $nsxtEdgeSnapshotStatus
                    }
                } else {
                    if ($PsBoundParameters.ContainsKey('allDomains')) {
                        $sddcManagerSnapshotStatus = Request-SddcManagerSnapshotStatus -server $server -user $user -pass $pass; $allSnapshotStatusObject += $sddcManagerSnapshotStatus
                        foreach ($domain in $allWorkloadDomains ) {
                            $vcenterSnapshotStatus = Request-VcenterSnapshotStatus -server $server -user $user -pass $pass -domain $domain.name; $allSnapshotStatusObject += $vcenterSnapshotStatus
                            $nsxtEdgeSnapshotStatus = Request-NsxtEdgeSnapshotStatus -server $server -user $user -pass $pass -domain $domain.name; $allSnapshotStatusObject += $nsxtEdgeSnapshotStatus
                        }
                    } else {
                        if ($singleWorkloadDomain.type -eq "MANAGEMENT") {
                            $sddcManagerSnapshotStatus = Request-SddcManagerSnapshotStatus -server $server -user $user -pass $pass; $allSnapshotStatusObject += $sddcManagerSnapshotStatus
                        }
                        $vcenterSnapshotStatus = Request-VcenterSnapshotStatus -server $server -user $user -pass $pass -domain $workloadDomain; $allSnapshotStatusObject += $vcenterSnapshotStatus
                        $nsxtEdgeSnapshotStatus = Request-NsxtEdgeSnapshotStatus -server $server -user $user -pass $pass -domain $workloadDomain; $allSnapshotStatusObject += $nsxtEdgeSnapshotStatus
                    }
                }

                if ($allSnapshotStatusObject.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $allSnapshotStatusObject = $allSnapshotStatusObject | Sort-Object Component, Resource, Element | ConvertTo-Html -Fragment -PreContent '<a id="infra-snapshot"></a><h3>Snapshot Status</h3>' -PostContent '<p>No issues found.</p>'
                } else {
                    $allSnapshotStatusObject = $allSnapshotStatusObject | Sort-Object Component, Resource, Element | ConvertTo-Html -Fragment -PreContent '<a id="infra-snapshot"></a><h3>Snapshot Status</h3>' -PostContent '<p>Only checks snapshots for SDDC Manager, vCenter Server instances, and NSX Edge nodes managed by SDDC Manager. By default, snapshots for NSX Local Manager cluster appliances are disabled and are not recommended.</p>' -As Table
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
            } else {
                if ($singleWorkloadDomain.type -eq "MANAGEMENT") {
                    $sddcPasswordExpiry = Request-SddcManagerUserExpiry -server $server -user $user -pass $pass -rootPass $sddcRootPass -failureOnly; $allPasswordExpiryObject += $sddcPasswordExpiry
                    $vrslcmPasswordExpiry = Request-vRslcmUserExpiry -server $server -user $user -pass $pass -failureOnly; $allPasswordExpiryObject += $vrslcmPasswordExpiry
                }
                $vcenterPasswordExpiry = Request-vCenterUserExpiry -server $server -user $user -pass $pass -workloadDomain $workloadDomain -failureOnly; $allPasswordExpiryObject += $vcenterPasswordExpiry
                $nsxtManagerPasswordExpiry = Request-NsxtManagerUserExpiry -server $server -user $user -pass $pass -domain $workloadDomain -failureOnly; $allPasswordExpiryObject += $nsxtManagerPasswordExpiry
                $nsxtEdgePasswordExpiry = Request-NsxtEdgeUserExpiry -server $server -user $user -pass $pass -domain $workloadDomain -failureOnly; $allPasswordExpiryObject += $nsxtEdgePasswordExpiry
            }
        } else {
            if ($PsBoundParameters.ContainsKey("allDomains")) {
                $sddcPasswordExpiry = Request-SddcManagerUserExpiry -server $server -user $user -pass $pass -rootPass $sddcRootPass; $allPasswordExpiryObject += $sddcPasswordExpiry
                $vrslcmPasswordExpiry = Request-vRslcmUserExpiry -server $server -user $user -pass $pass; $allPasswordExpiryObject += $vrslcmPasswordExpiry
                $vcenterPasswordExpiry = Request-vCenterUserExpiry -server $server -user $user -pass $pass -alldomains; $allPasswordExpiryObject += $vcenterPasswordExpiry
                $allWorkloadDomains = Get-VCFWorkloadDomain
                foreach ($domain in $allWorkloadDomains ) {
                    $nsxtManagerPasswordExpiry = Request-NsxtManagerUserExpiry -server $server -user $user -pass $pass -domain $domain.name; $allPasswordExpiryObject += $nsxtManagerPasswordExpiry
                    $nsxtEdgePasswordExpiry = Request-NsxtEdgeUserExpiry -server $server -user $user -pass $pass -domain $domain.name; $allPasswordExpiryObject += $nsxtEdgePasswordExpiry
                }
            } else {
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

                if ($sddcManagerStorageHealth.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $sddcManagerStorageHealth = $sddcManagerStorageHealth | ConvertTo-Html -Fragment -PreContent '<a id="storage-sddcmanager"></a><h3>SDDC Manager Disk Health Status</h3>' -PostContent '<p>No Issues Found.</p>'
                } else {
                    $sddcManagerStorageHealth = $sddcManagerStorageHealth | ConvertTo-Html -Fragment -PreContent '<a id="storage-sddcmanager"></a><h3>SDDC Manager Disk Health Status</h3>' -As Table
                }
                $sddcManagerStorageHealth = Convert-CssClass -htmldata $sddcManagerStorageHealth

                if ($allVcenterStorageHealth.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $allVcenterStorageHealth = $allVcenterStorageHealth | Sort-Object FQDN, Filesystem | ConvertTo-Html -Fragment -PreContent '<a id="storage-vcenter"></a><h3>vCenter Server Disk Health</h3>' -PostContent '<p>No Issues Found.</p>'
                } else {
                    $allVcenterStorageHealth = $allVcenterStorageHealth | Sort-Object  FQDN, Filesystem | ConvertTo-Html -Fragment -PreContent '<a id="storage-vcenter"></a><h3>vCenter Server Disk Health</h3>' -As Table
                }
                $allVcenterStorageHealth = Convert-CssClass -htmldata $allVcenterStorageHealth

                if ($allEsxiStorageCapacity.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $allEsxiStorageCapacity = $allEsxiStorageCapacity | Sort-Object Domain, 'ESXi FQDN', 'Volume Name' | ConvertTo-Html -Fragment -PreContent '<a id="storage-esxi"></a><h3>ESXi Host Local Volume Capacity</h3>' -PostContent '<p>No Issues Found.</p>'
                } else {
                    $allEsxiStorageCapacity = $allEsxiStorageCapacity | Sort-Object Domain, 'ESXi FQDN', 'Volume Name' | ConvertTo-Html -Fragment -PreContent '<a id="storage-esxi"></a><h3>ESXi Host Local Volume Capacity</h3>' -As Table
                }
                $allEsxiStorageCapacity = Convert-CssClass -htmldata $allEsxiStorageCapacity

                if ($allDatastoreStorageCapacity.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $allDatastoreStorageCapacity = $allDatastoreStorageCapacity | Sort-Object 'vCenter Server', 'Datastore Name' | ConvertTo-Html -Fragment -PreContent '<a id="storage-datastore"></a><h3>Datastore Space Usage Report</h3>' -PostContent '<p>No Issues Found.</p>'
                } else {
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
                            } else {
                                $customObject += $elementObject
                            }
                            $elementObject = Request-LocalUserExpiry -fqdn $server -component SDDC -rootPass $rootPass -checkUser root
                            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                    $customObject += $elementObject
                                }
                            } else {
                                $customObject += $elementObject
                            }
                            $elementObject = Request-LocalUserExpiry -fqdn $server -component SDDC -rootPass $rootPass -checkUser vcf
                            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                    $customObject += $elementObject
                                }
                            } else {
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
                                            $rootPass = (Get-VCFCredential | Where-Object { $_.credentialType -eq 'SSH' -and $_.resource.resourceName -eq $vcfNsxDetails.fqdn -and $_.resource.domainName -eq $domain }).password
                                            $elementObject = Request-LocalUserExpiry -fqdn $nsxtEdgeNode.hostname -component 'NSX Edge' -rootPass $rootPass -checkUser admin
                                            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                                if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                                    $customObject += $elementObject
                                                }
                                            } else {
                                                $customObject += $elementObject
                                            }
                                            $elementObject = Request-LocalUserExpiry -fqdn $nsxtEdgeNode.hostname -component 'NSX Edge' -rootPass $rootPass -checkUser audit
                                            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                                if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                                    $customObject += $elementObject
                                                }
                                            } else {
                                                $customObject += $elementObject
                                            }
                                            $elementObject = Request-LocalUserExpiry -fqdn $nsxtEdgeNode.hostname -component 'NSX Edge' -rootPass $rootPass -checkUser root
                                            if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                                if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                                    $customObject += $elementObject
                                                }
                                            } else {
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
                                    $nsxtManagerNode = ($vcfNsxDetails.nodes | Select-Object -First 1)
                                    $rootPass = (Get-VCFCredential | Where-Object { $_.credentialType -eq 'SSH' -and $_.resource.resourceName -eq $vcfNsxDetails.fqdn -and $_.resource.domainName -eq $domain }).password
                                    $elementObject = Request-LocalUserExpiry -fqdn $nsxtManagerNode.fqdn -component 'NSX Manager' -rootPass $rootPass -checkUser admin
                                    if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                        if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                            $customObject += $elementObject
                                        }
                                    } else {
                                        $customObject += $elementObject
                                    }
                                    $elementObject = Request-LocalUserExpiry -fqdn $nsxtManagerNode.fqdn -component 'NSX Manager' -rootPass $rootPass -checkUser audit
                                    if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                        if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                            $customObject += $elementObject
                                        }
                                    } else {
                                        $customObject += $elementObject
                                    }
                                    $elementObject = Request-LocalUserExpiry -fqdn $nsxtManagerNode.fqdn -component 'NSX Manager' -rootPass $rootPass -checkUser root
                                    if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                        if (($elementObject.alert -eq 'RED') -or ($elementObject.alert -eq 'YELLOW')) {
                                            $customObject += $elementObject
                                        }
                                    } else {
                                        $customObject += $elementObject
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
                        if (Test-NSXTAuthentication -server $vcfNsxDetails.fqdn -user ($vcfNsxDetails.adminUser | Select-Object -first 1) -pass ($vcfNsxDetails.adminPass | Select-Object -first 1)) {
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
                                $messageState = 'but unhealthy.' # Set the alert message
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
                            } else {
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
                        if (Test-NSXTAuthentication -server $vcfNsxDetails.fqdn -user ($vcfNsxDetails.adminUser | Select-Object -First 1) -pass ($vcfNsxDetails.adminPass | Select-Object -First 1)) {
                            $computeManagers = (Get-NsxtComputeManager)
                            foreach ($computeManager in $computeManagers) {
                                $customObject = New-Object System.Collections.ArrayList
                                $component = 'Compute Manager' # Define the component name
                                $resource = $vcfNsxDetails.fqdn # Define the resource name

                                # Set the alert and message based on the status of the compute manager
                                if ($computeManager.server -notin (( Get-VCFWorkloadDomain | Where-Object { $_.nsxtCluster.vipFqdn -eq $vcfNsxDetails.fqdn }).vcenters.fqdn) ) {
                                    $alert = 'RED' # Critical; rogue addition detected
                                    $message = "$($computeManager.server) has been detected as a rogue addition." # Critical; rogue addition detected
                                } else {
                                    $status = (Get-NsxtComputeManagerStatus -id $computeManager.id)
                                    if ($status.registration_status -eq 'REGISTERED' -and $status.connection_status -eq 'UP') {
                                    $alert = 'GREEN' # Ok; registered and up
                                    $message = "$($computeManager.server) is registered and healthy." # Ok; registered and up
                                } elseif ($status.registration_status -eq 'REGISTERED' -and $status.connection_status -ne 'UP') {
                                    $alert = 'RED' # Critical; registered and not up
                                    $message = "$($computeManager.server) is registered but unhealthy." # Critical; registered and not up
                                } else {
                                    $alert = 'RED' # Critical; not registered
                                    $message = "$($computeManager.server) is not registered." # Critical; not registered
                                }
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
                                } else {
                                    $customObject += $elementObject
                                }
                                $outputObject += $customObject
                            }
                        }
                        $outputObject | Sort-Object Component, Resource
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
                            $snapshotCount = ($snapshotStatus | Measure-Object).count
                            $snapshotLast = $snapshotStatus.Created | select -Last 1
                            $snapshotAge = [math]::Ceiling(((Get-Date) - ([DateTime]$snapshotLast)).TotalDays)

                            # Set the alert color based on the age of the snapshot
                            if ($snapshotCount -eq 0) {
                                $alert = 'GREEN' # Ok; = 0 snapshots
                                $message = 'No snapshots exist.'
                            } elseif ($snapshotAge -le 1) {
                                $alert = 'GREEN' # OK; <= 1 days
                                $message = 'Latest snapshot is less than 1 day old. '
                            } elseif ($snapshotAge -gt 1 -and $snapshotAge -le 3) {
                                $alert = 'YELLOW' # Warning; > 1 days and <= 3 days
                                $message = 'Latest snapshot is greater than 1 day old. '
                            } elseif ($snapshotAge -gt 3) {
                                $alert = 'RED' # Critical; >= 7 days
                                $message = 'Latest snapshot is greater than 3 days old. '
                            }

                            # Set the alert color based on the number of snapshots.
                            if ($snapshotCount -eq 1) {
                                $messageCount = 'A single snapshot exists. '
                            } elseif ($snapshotCount -gt 1) {
                                $messageCount = 'More than 1 snapshot exist. '
                            }
                            $message += $messageCount # Combine the alert message

                            # Set the alert message based on the snapshot consolidation status.
                            if (Get-SnapshotConsolidation -vm ($server.Split('.')[0])) {
                                $alert = 'RED' # Critical; Consolidation is required
                                $consolidationRequired = $true
                                $messageConsolidation += 'Snapshot consolidation is required.'
                            } else {
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
                            } else {
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
        Request-VcenterSnapshotStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will publish the snapshot status for a vCenter Server instance for a specific workload domain.

        .EXAMPLE
        Request-VcenterSnapshotStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
        This example will publish the snapshot status for a vCenter Server instance for a specific workload domain, but only failed items.
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
                $vcenter = (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $domain }).vcenters
                $vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT
                if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                    if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                        $customObject = New-Object System.Collections.ArrayList
                        $component = 'vCenter Server'
                        $resource = 'vCenter Server Snapshot'
                        $domain = (Get-VCFWorkloadDomain | Where-Object { $_.vcenters.fqdn -eq $vcenter.fqdn }).name
                        $snapshotStatus = Get-SnapshotStatus -vm ($vcenter.fqdn.Split('.')[0])
                        $snapshotCount = ($snapshotStatus | Measure-Object).count
                        $snapshotLast = $snapshotStatus.Created | select -Last 1
                        $snapshotAge = [math]::Ceiling(((Get-Date) - ([DateTime]$snapshotLast)).TotalDays)

                        # Set the alert color based on the age of the snapshot
                        if ($snapshotCount -eq 0) {
                            $alert = 'GREEN' # Ok; = 0 snapshots
                            $message = 'No snapshots exist.'
                        } elseif ($snapshotAge -le 1) {
                            $alert = 'GREEN' # OK; <= 1 days
                            $message = 'Latest snapshot is less than 1 day old. '
                        } elseif ($snapshotAge -gt 1 -and $snapshotAge -le 3) {
                            $alert = 'YELLOW' # Warning; > 1 days and <= 3 days
                            $message = 'Latest snapshot is greater than 1 day old. '
                        } elseif ($snapshotAge -gt 3) {
                            $alert = 'RED' # Critical; >= 7 days
                            $message = 'Latest snapshot is greater than 3 days old. '
                        }

                        # Set the alert message based on the number of snapshots.
                        if ($snapshotCount -eq 1) {
                            $messageCount = 'A single snapshot exists. '
                        } elseif ($snapshotCount -gt 1) {
                            $messageCount = 'More than 1 snapshot exist. '
                        }
                        $message += $messageCount # Combine the alert message

                        # Set the alert message based on the snapshot consolidation status.
                        if (Get-SnapshotConsolidation -vm ($vcenter.fqdn.Split('.')[0])) {
                            $alert = 'RED' # Critical; Consolidation is required
                            $consolidationRequired = $true
                            $messageConsolidation += 'Snapshot consolidation is required.'
                        } else {
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
                        } else {
                            $customObject += $elementObject
                        }
                        $outputObject += $customObject # Add the custom object to the output object
                    }
                    Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
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
        Request-NsxtEdgeSnapshotStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will publish the snapshot status for all NSX Edge nodes managed by SDDC Manager for a specific workload domain.

        .EXAMPLE
        Request-NsxtEdgeSnapshotStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
        This example will publish the snapshot status for all NSX Edge nodes managed by SDDC Manager for a specific workload domain. but only failed items.
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
                $nsxtManager = Get-VCFNsxtCluster | Where-Object { $_.domains.name -eq $domain }
                if ($nsxtEdgeDetails = Get-VCFEdgeCluster | Where-Object { $_.nsxtCluster.vipfqdn -eq $nsxtManager.vipFqdn }) {
                    foreach ($nsxtEdgeNode in $nsxtEdgeDetails.edgeNodes) {
                        if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain)) {
                            if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                                if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                                    $customObject = New-Object System.Collections.ArrayList
                                    $message = ''
                                    $component = 'NSX'
                                    $resource = 'NSX Edge Node Snapshot'
                                    $domain = $domain
                                    $snapshotStatus = Get-SnapshotStatus -vm ($nsxtEdgeNode.hostName.Split('.')[0])
                                    $snapshotCount = ($snapshotStatus | Measure-Object).count
                                    $snapshotLast = $snapshotStatus.Created | select -Last 1
                                    $snapshotAge = [math]::Ceiling(((Get-Date) - ([DateTime]$snapshotLast)).TotalDays)

                                    # Set the alert color based on the age of the snapshot
                                    if ($snapshotCount -eq 0) {
                                        $alert = 'GREEN' # Ok; = 0 snapshots
                                        $message = 'No snapshots exist.'
                                    } elseif ($snapshotAge -le 1) {
                                        $alert = 'GREEN' # OK; <= 1 days
                                        $message = 'Latest snapshot is less than 1 day old. '
                                    } elseif ($snapshotAge -gt 1 -and $snapshotAge -le 3) {
                                        $alert = 'YELLOW' # Warning; > 1 days and <= 3 days
                                        $message = 'Latest snapshot is greater than 1 day old. '
                                    } elseif ($snapshotAge -gt 3) {
                                        $alert = 'RED' # Critical; >= 7 days
                                        $message = 'Latest snapshot is greater than 3 days old. '
                                    }

                                    # Set the alert message based on the number of snapshots.
                                    if ($snapshotCount -eq 1) {
                                        $messageCount = 'A single snapshot exists. '
                                    } elseif ($snapshotCount -gt 1) {
                                        $messageCount = 'More than 1 snapshot exist. '
                                    }
                                    $message += $messageCount # Combine the alert message

                                    # Set the alert message based on snapshots consolidation status.
                                    if (Get-SnapshotConsolidation -vm ($nsxtEdgeNode.hostName.Split('.')[0])) {
                                        $alert = 'RED' # Critical; Consolidation is required
                                        $consolidationRequired = $true
                                        $messageConsolidation += 'Snapshot consolidation is required.'
                                    } else {
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
        }
        $outputObject | Sort-Object Component, Resource, Element
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
                $customObject = New-Object System.Collections.ArrayList
                $component = 'SDDC Manager' # Define the component name
                $resource = 'SDDC Manager Backup Operation' # Define the resource name
                $domain = (Get-VCFWorkloadDomain | Sort-Object -Property type, name).name -join ',' # Define the domain(s)
                $backupTask = Get-VCFTask | Where-Object { $_.type -eq 'SDDCMANAGER_BACKUP' } | Select-Object -First 1
                if ($backupTask) {
                    if ($PSEdition -eq 'Core') {
                        $date = $backupTask.creationTimestamp
                    } else {
                        $date = [DateTime]::ParseExact($backupTask.creationTimestamp, 'yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture) # Define the date
                    }
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

                    # Set the alert and message if the backup is located on the SDDC Manager
                    $backupServer = (Get-VCFBackupConfiguration).server # Get the backup server

                    if ($backupServer -eq (Get-VCFManager).fqdn -or $backupServer -eq (Get-VCFManager).ipAddress) {
                        $alert = "RED" # Critical; backup server is located on the SDDC Manager
                        $messageBackupServer = "Backup is located on the SDDC Manager ($server). Reconfigure backups to use another location." # Set the alert message
                        $message = $messageBackupServer # Override the message
                    }
                } else {
                    $alert = "RED" # Critical; backup is not configured
                    $message = "Backup is not configured." # Set the alert message
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

                                if ($backupServer -eq (Get-VCFManager).fqdn -or $backupServer -eq (Get-VCFManager).ipAddress) {
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

                                # Set the alert and message if the backup is located on the SDDC Manager
                                $backupServer = (Get-NsxtBackupConfiguration -fqdn $vcfNsxDetails.fqdn).remote_file_server.server # Get the backup server

                                if ($backupServer -eq (Get-VCFManager).fqdn -or $backupServer -eq (Get-VCFManager).ipAddress) {
                                    $alert = 'RED' # Critical; backup server is located on the SDDC Manager
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

                                # Set the alert and message if the backup is located on the SDDC Manager
                                $backupServer = (Get-NsxtBackupConfiguration -fqdn $vcfNsxDetails.fqdn).remote_file_server.server # Get the backup server

                                if ($backupServer -eq (Get-VCFManager).fqdn -or $backupServer -eq (Get-VCFManager).ipAddress) {
                                    $alert = 'RED' # Critical; backup server is located on the SDDC Manager
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
                    Request-VcenterApiToken -fqdn $vcfVcenterDetails.fqdn -username $vcfVcenterDetails.ssoAdmin -password $vcfVcenterDetails.ssoAdminPass | Out-Null
                    $customObject = New-Object System.Collections.ArrayList
                    $component = 'vCenter Server' # Define the component name
                    $resource = 'vCenter Server Backup Operation' # Define the resource name
                    if ($global:backupTask = (Get-VcenterBackupStatus | Select-Object -Last 1).Value) {
                        if ($PSEdition -eq 'Core') {
                            $timestamp = $backupTask.end_time
                        } else {
                            $timestamp = [DateTime]::ParseExact($backupTask.end_time, 'yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture) # Define the date
                        }
                            if ($timestamp) {
                            $backupAge = [math]::Ceiling(((Get-Date) - ([DateTime]$timestamp)).TotalDays) # Calculate the number of days since the backup was created
                        } else {
                            $backupAge = 0 # Set the backup age to 0 if not available
                        }

                        # Set the status for the backup task
                        if ($backupTask.status -eq 'SUCCEEDED') {
                            $alert = "GREEN" # Ok; success
                        } elseif ($backupTask.status -eq 'IN PROGRESS') {
                            $alert = "YELLOW" # Warning; in progress
                        } else {
                            $alert = "RED" # Critical; failure
                        }

                        if ($timestamp) {
                            # Set the message for the backup task
                            if ([String]::IsNullOrEmpty($backupTask.messages)) {
                                $message = "The backup completed without errors. " # Ok; success
                            } else {
                                $message = "The backup failed with errors. Please investigate before proceeding. " # Critical; failure
                            }
                        }

                        # Set the alert and message update for the backup task based on the age of the backup
                        if ($backupAge -eq 0) {
                            $alert = "RED" # Critical; 0 days
                            $messageBackupAge = "Backup has not completed." # Set the alert message
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

                        # Set the alert and message if the backup is located on the SDDC Manager
                        $backupLocation = $backupTask.location # Get the backup server
                        $backupServer = (($backupLocation -Split ('sftp://'))[-1] -Split ('/'))[0]

                        if ($backupServer -eq (Get-VCFManager).fqdn -or $backupServer -eq (Get-VCFManager).ipAddress) { # Compare against the `host` attribute
                            $alert = 'RED' # Critical; backup server is located on the SDDC Manager
                            $messageBackupServer = "Backup is located on the SDDC Manager ($server). Reconfigure backups to use another location." # Set the alert message
                            $message = $messageBackupServer # Override the message
                        }
                    } else {
                        $alert = "RED" # Critical; backup job no
                        $message = "Backup is not configured." # Set the alert message
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
                            } else {
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
        $dfOutput = Invoke-SddcCommand -server $server -user $user -pass $pass -vmUser root -vmPass $rootPass -command $command # Get Disk Information from SDDC Manager

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
            } else {
                $vcenterConnectivity = Request-VcenterAuthentication -server $server -user $user -pass $pass -workloadDomain $workloadDomain -failureOnly; $allConnectivityObject += $vcenterConnectivity
                $NsxtConnectivity = Request-NsxtAuthentication -server $server -user $user -pass $pass -workloadDomain $workloadDomain -failureOnly; $allConnectivityObject += $NsxtConnectivity
            }
            $connectivityRaw = Publish-ConnectivityHealth -json $json -failureOnly
        } else {
            if ($PsBoundParameters.ContainsKey("allDomains")) {
                $vcenterConnectivity = Request-VcenterAuthentication -server $server -user $user -pass $pass -alldomains; $allConnectivityObject += $vcenterConnectivity
                $NsxtConnectivity = Request-NsxtAuthentication -server $server -user $user -pass $pass -alldomains; $allConnectivityObject += $NsxtConnectivity
            } else {
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
                        } else {
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
                        } else {
                            $customObject += $elementObject
                        }
                    }
                } else {
                    $vcenter = (Get-VCFWorkloadDomain | Where-Object {$_.name -eq $workloadDomain}).vcenters.fqdn
                    if (Test-vSphereApiAuthentication -server $vcenter -user $account.username -pass $account.password) {
                        $alert = "GREEN"
                        $message = "API Connection check successful!"
                    } else {
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
                    } else {
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
                                } else {
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
                            } else {
                                $customObject += $elementObject
                            }
                        }
                    }
                } else {
                    $vcfNsxDetails = Get-NsxtServerDetail -fqdn $server -username $user -password $pass -domain $workloadDomain -listNodes
                    foreach ($node in $vcfNsxDetails.nodes) {
                        if (Test-NsxtConnection -server $node.fqdn -ErrorAction SilentlyContinue -ErrorVariable ErrorMessage ) {
                            if (Test-NsxtAuthentication -server $node.fqdn -user ($vcfNsxDetails.adminUser | Select-Object -first 1) -pass ($vcfNsxDetails.adminPass | Select-Object -first 1)) {
                                $alert = "GREEN"
                                $message = "API Connection check successful!"
                            } else {
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
                        } else {
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
                                $resource = $vcfNsxDetails.fqdn # Define the resource name
                                $transportNodeStatus = (Get-NsxtTransportNodeStatus -type $type) # Get the status of the transport nodes
                                $nodeType = (Get-Culture).textinfo.ToTitleCase($type.ToLower()) # Convert the type to title case
                                # Set the alert and message based on the status of the transport node
                                if ($downCount -ge 0 -or $unknownCount -ge 0) {
                                    $alert = 'RED' # Critical, transport node(s) down or unknown
                                    $message = $nodeType + ' transport node(s) in down or unknown state.' # Set the alert message
                                } elseif ($degradedCount -ge 0) {
                                    $alert = 'YELLOW' # Warning, transport node(s) degraded
                                    $message = $nodeType + ' transport node(s) in degraded state.' #
                                } else {
                                    $alert = 'GREEN' # OK, transport node(s)  up
                                    $message = $nodeType + ' transport node(s) in up state.' # Set the alert message
                                }
                                # Add the properties to the element object
                                $elementObject = New-Object -TypeName psobject
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
                                } else {
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

Function Request-NsxtTransportNodeTunnelStatus {
    <#
        .SYNOPSIS
        Returns the status of NSX transport node tunnels.

        .DESCRIPTION
        The Request-NsxtTransportNodeTunnelStatus cmdlet returns the status NSX transport nodes tunnels.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates network connectivity and authentication to the SDDC Manager instanc
        - Gathers the details for the NSX Manager cluster from the SDDC Manager
        - Validates network connectivity and authentication to the NSX Local Manager cluster
        - Collects the status of the transport node tunnels

        .EXAMPLE
        Request-NsxtTransportNodeTunnelStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example will return the status of the NSX transport node tunnels for a workload domain.

        .EXAMPLE
        Request-NsxtTransportNodeTunnelStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
        This example will return the status of the NSX transport node tunnels for a workload domain but only reports issues.
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
                                $transportNodes = Get-NsxtTransportNode -type $type
                                foreach ($transportNode in $transportNodes) {
                                    $resource = $vcfNsxDetails.fqdn # Define the resource name
                                    $nodeType = (Get-Culture).textinfo.ToTitleCase($type.ToLower()) # Convert the type to title case
                                    $tunnels = (Get-NsxtTransportNodeTunnel -id $transportNode.id).tunnels # Get the tunnels for the transport node
                                    foreach ($tunnel in $tunnels) {
                                        # Set the alert and message based on the status of the tunnel
                                        if ($tunnel.status -eq 'UP') {
                                            $alert = 'GREEN' # OK, transport node up
                                            $message = $nodeType + ' transport node tunnel is up.' # Set the alert message
                                        } else {
                                            $alert = 'RED' # Critical, transport node down or unknown
                                            $message = $nodeType + ' transport node tunnel is down or in unknown state.' # Set the alert message
                                        }
                                        # Update the alert and message based on the status of BFD
                                        if ($tunnel.bfd.state -ne 'UP') {
                                            $alert = 'YELLOW' # WARNING, BFD down or unknown
                                            $message = "Bidirectional forwarding is down or in unknown state. Run '(Get-NsxtTransportNodeTunnelStatus -id $($transportNode.id)).tunnels' for more information." # Set the alert message
                                        }
                                        # Add the properties to the element object
                                        $elementObject = New-Object -TypeName psobject
                                        $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $resource # Set the resource name
                                        $elementObject | Add-Member -NotePropertyName 'Element' -NotePropertyValue $nodeType # Set the element name
                                        $elementObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain # Set the domain
                                        $elementObject | Add-Member -NotePropertyName 'Source IP' -NotePropertyValue $tunnel.local_ip # Set the source IP
                                        $elementObject | Add-Member -NotePropertyName 'Remote IP' -NotePropertyValue $tunnel.remote_ip # Set the remote IP
                                        $elementObject | Add-Member -NotePropertyName 'Source Node' -NotePropertyValue $transportNode.display_name # Set the source name
                                        $elementObject | Add-Member -NotePropertyName 'Remote Node' -NotePropertyValue $tunnel.remote_node_display_name # Set the source name
                                        $elementObject | Add-Member -NotePropertyName 'Interface' -NotePropertyValue $tunnel.egress_interface # Set the egress interface
                                        $elementObject | Add-Member -NotePropertyName 'Status' -NotePropertyValue $tunnel.status # Set the status
                                        $elementObject | Add-Member -NotePropertyName 'BFD' -NotePropertyValue $tunnel.bfd.state # Set the BFD status
                                        $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert # Set the alert
                                        $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue "$message" # Set the message
                                        if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                            if ($elementObject.alert -eq 'RED' -or $elementObject.alert -eq 'YELLOW') {
                                                $customObject += $elementObject
                                            }
                                        } else {
                                            $customObject += $elementObject
                                        }
                                    }
                                }
                                $outputObject += $customObject
                            }
                        }
                        $outputObject | Sort-Object Domain, Resource, Element, 'Local Transport Node', Interface
                    }
                }
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-NsxtTransportNodeTunnelStatus

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
                            if ($tier0s = Get-NsxtTier0Gateway) {
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

Function Publish-VmConnectedCdrom {
    <#
        .SYNOPSIS
        Publish the status of virtual machines with connected CD-ROMs in a workload domain in HTML format.

        .DESCRIPTION
        The Publish-VmConnectedCdrom cmdlet returns the status of virtual machines with connected CD-ROMS in a workload
        domain in HTML format. The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Server instance
        - Validates the authentication to vCenter Server with credentials from SDDC Manager
        - Publishes information

        .EXAMPLE
        Publish-VmConnectedCdrom -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will returns the status of virtual machines with connected CD-ROMs in all workload domains.

        .EXAMPLE
        Publish-VmConnectedCdrom -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will returns the status of virtual machines with connected CD-ROMs in a workload domain.
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
                $allHealthObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('allDomains')) {
                    $allWorkloadDomains = Get-VCFWorkloadDomain
                    foreach ($domain in $allWorkloadDomains ) {
                        $vmConnectedCdrom = Request-VmConnectedCdrom -server  $server -user $user -pass $pass -domain $domain.name; $allHealthObject += $vmConnectedCdrom
                    }
                } else {
                    $vmConnectedCdrom = Request-VmConnectedCdrom -server  $server -user $user -pass $pass -domain $workloadDomain; $allHealthObject += $vmConnectedCdrom
                }

                if ($allHealthObject.Count -eq 0) { $addNoIssues = $true }

                if ($addNoIssues) {
                    $allHealthObject = $allHealthObject | ConvertTo-Html -Fragment -PreContent '<a id="storage-vm-cdrom"></a><h3>Virtual Machines with Connected CD-ROMs</h3>' -PostContent '<p>No virtual machines with connected CD-ROMs found.</p>'
                } else {
                    $allHealthObject = $allHealthObject | Sort-Object Cluster, 'VM Name' | ConvertTo-Html -Fragment -PreContent '<a id="storage-vm-cdrom"></a><h3>Virtual Machines with Connected CD-ROMs</h3>' -As Table
                }
                $allHealthObject = Convert-CssClass -htmlData $allHealthObject
                $allHealthObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-VmConnectedCdrom

Function Request-VmConnectedCdrom {
    <#
		.SYNOPSIS
        Returns the status of virtual machines with connected CD-ROMs in a workload domain.

        .DESCRIPTION
        The Request-VmConnectedCdrom cmdlet returns the status of virtual machines with connected CD-ROMs in a workload
        domain. The cmdlet connects to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Gathers the status of virtual machines with connected CD-ROMs in a workload domain.

        .EXAMPLE
        Request-VmConnectedCdrom -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example returns the status of virtual machines with connected CD-ROMs in a workload domain.
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
                            $allClustersObject = New-Object System.Collections.ArrayList
                            $allClusters = Get-Cluster -Server $vcfVcenterDetails.fqdn
                            foreach ($cluster in $allClusters) {
                                $allVms = Get-VM -Server $vcfVcenterDetails.fqdn | Where-Object { $_ | Get-CDDrive | Where-Object { $_.ConnectionState.Connected -eq 'true' } } | Select-Object Name, @{Name = 'ISO Path'; Expression = { (Get-CDDrive $_).isopath } }
                                foreach ($vm in $allVms) {
                                    # Set the alert and message based on the CD-ROM connection
                                    $alert = 'YELLOW' # Warning, connected CD-ROM
                                    $message = 'A virtual CD-ROM is connected.' # Set the status message
                                    # Set the object properties
                                    $customObject = New-Object -TypeName psobject
                                    $customObject | Add-Member -NotePropertyName 'vCenter Server' -NotePropertyValue $vcfVcenterDetails.fqdn
                                    $customObject | Add-Member -NotePropertyName 'Cluster' -NotePropertyValue $cluster.Name
                                    $customObject | Add-Member -NotePropertyName 'VM Name' -NotePropertyValue $vm.Name
                                    $customObject | Add-Member -NotePropertyName 'ISO Path' -NotePropertyValue $vm.'ISO Path'
                                    $customObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
                                    $customObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $message
                                    $allClustersObject += $customObject
                                }
                            }
                            $allClustersObject | Sort-Object Cluster, 'VM Name', 'ISO Path'
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
Export-ModuleMember -Function Request-VmConnectedCdrom

Function Publish-EsxiConnectionHealth {
    <#
        .SYNOPSIS
        Publish the connection status of ESXi hosts in a workload domain in HTML format.

        .DESCRIPTION
        The Publish-EsxiConnectionHealth cmdlet returns the status of virtual machines with connected CD-ROMS in a workload
        domain in HTML format. The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Server instance
        - Validates the authentication to vCenter Server with credentials from SDDC Manager
        - Publishes information

        .EXAMPLE
        Publish-EsxiConnectionHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will publish the connection status of ESXi hosts in all workload domains.

        .EXAMPLE
        Publish-EsxiConnectionHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will publish the connection status of ESXi hosts in a workload domain.

        .EXAMPLE
        Publish-EsxiConnectionHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -failureOnly
        This example will publish the connection status of ESXi hosts in all workload domains but only for failures.
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
                $allHealthObject = New-Object System.Collections.ArrayList
                $allWorkloadDomains = Get-VCFWorkloadDomain
                if ($PsBoundParameters.ContainsKey("allDomains") -and $PsBoundParameters.ContainsKey("failureOnly")) {
                    foreach ($domain in $allWorkloadDomains ) {
                        $esxiConnectionStatus = Request-EsxiConnectionHealth -server  $server -user $user -pass $pass -domain $domain.name -failureOnly; $allHealthObject += $esxiConnectionStatus
                    }
                } elseif ($PsBoundParameters.ContainsKey("allDomains")) {
                    foreach ($domain in $allWorkloadDomains ) {
                        $esxiConnectionStatus = Request-EsxiConnectionHealth -server  $server -user $user -pass $pass -domain $domain.name; $allHealthObject += $esxiConnectionStatus
                    }
                }

                if ($PsBoundParameters.ContainsKey("workloadDomain") -and $PsBoundParameters.ContainsKey("failureOnly")) {
                    $esxiConnectionStatus = Request-EsxiConnectionHealth -server  $server -user $user -pass $pass -domain $workloadDomain -failureOnly; $allHealthObject += $esxiConnectionStatus
                } elseif ($PsBoundParameters.ContainsKey("workloadDomain")) {
                    $esxiConnectionStatus = Request-EsxiConnectionHealth -server  $server -user $user -pass $pass -domain $workloadDomain; $allHealthObject += $esxiConnectionStatus
                }

                if ($allHealthObject.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $allHealthObject = $allHealthObject | ConvertTo-Html -Fragment -PreContent '<a id="esxi-connection"></a><h3>ESXi Connection Health</h3>' -PostContent '<p>No issues found.</p>'
                } else {
                    $allHealthObject = $allHealthObject | Sort-Object Resource, Cluster | ConvertTo-Html -Fragment -PreContent '<a id="esxi-connection"></a><h3>ESXi Connection Health</h3>' -As Table
                }
                $allHealthObject = Convert-CssClass -htmlData $allHealthObject
                $allHealthObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-EsxiConnectionHealth

Function Request-EsxiConnectionHealth {
    <#
		.SYNOPSIS
        Returns the connection status of ESXi hosts in a workload domain.

        .DESCRIPTION
        The Request-EsxiConnectionHealth cmdlet returns the connection status of ESXi hosts in a workload domain.
        The cmdlet connects to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Gathers the connection status of ESXi hosts in a workload domain.

        .EXAMPLE
        Request-EsxiConnectionHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
        This example returns the connection status of ESXi hosts in a workload domain.

        .EXAMPLE
        Request-EsxiConnectionHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
        This example returns the connection status of ESXi hosts in a workload domain but only reports issues.
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
                            $allClustersObject = New-Object System.Collections.ArrayList
                            $allClusters = Get-Cluster -Server $vcfVcenterDetails.fqdn
                            foreach ($cluster in $allClusters) {
                                $esxihosts = Get-VMHost -Server $vcfVcenterDetails.fqdn
                                foreach ($esxiHost in $esxiHosts) {
                                    $component = "ESXi"
                                    # Set the alert and message based on the CD-ROM connection
                                    if ($esxiHost.ConnectionState -eq 'Connected') {
                                        $alert = 'GREEN' # Ok, connected
                                        $message = 'Host is connected.' # Set the status message
                                    } elseif ($esxiHost.ConnectionState -eq 'Maintenance') {
                                        $alert = 'YELLOW' # Warning, maintenance
                                        $message = 'Host is in maintenance mode.' # Set the status message
                                    } elseif ($esxiHost.ConnectionState -eq 'Disconnected') {
                                        $alert = 'RED' # Critical, disconnected
                                        $message = 'Host is disconnected.' # Set the status message
                                    } else {
                                        $alert = 'RED' # Critical, unknown state
                                        $message = 'Host is in an unknown state.' # Set the status message
                                    }
                                    # Set the object properties
                                    $customObject = New-Object -TypeName psobject
                                    $customObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component
                                    $customObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $esxiHost.Name
                                    $customObject | Add-Member -NotePropertyName 'Cluster' -NotePropertyValue $cluster.Name
                                    $customObject | Add-Member -NotePropertyName 'Connection' -NotePropertyValue $esxiHost.ConnectionState
                                    $customObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
                                    $customObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $message

                                    if ($PsBoundParameters.ContainsKey('failureOnly')) {
                                        if ($esxiHost.ConnectionState -ne 'Connected' ) {
                                            $allClustersObject += $customObject
                                        }
                                    } else {
                                        $allClustersObject += $customObject
                                    }
                                }
                            }
                            $allClustersObject | Sort-Object Resource, Cluster
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
Export-ModuleMember -Function Request-EsxiConnectionHealth

Function Publish-SddcManagerFreePool {
    <#
        .SYNOPSIS
        Publish SDDC Manager free pool health information in HTML format.

        .DESCRIPTION
        The Publish-SddcManagerFreePool cmdlet returns SDDC Manager free pool information in HTML format.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates the network connectivity and authentication to the SDDC Manager instance
        - Publishes information

        .EXAMPLE
        Publish-SddcManagerFreePool -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
        This example will return the free pool health from SDDC Manager.

        .EXAMPLE
        Publish-SddcManagerFreePool -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -failureOnly
        This example will return the free pool health from SDDC Manager and return the failures only.
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
                $allConfigurationObject = New-Object System.Collections.ArrayList
                $unassignedEsxiHosts = (Get-VCFHost | Where-Object {$_.status -eq "UNASSIGNED_USEABLE"})
                if ($unassignedEsxiHosts.Count -gt 0) {
                    if ($PsBoundParameters.ContainsKey('failureOnly')) {
                        $allConfigurationObject = Request-SddcManagerFreePool -server $server -user $user -pass $pass -failureOnly
                    }
                    else {
                        $allConfigurationObject = Request-SddcManagerFreePool -server $server -user $user -pass $pass
                    }

                    if ($allConfigurationObject.Count -eq 0) { $addNoIssues = $true }
                    if ($addNoIssues) {
                        $allConfigurationObject = $allConfigurationObject | ConvertTo-Html -Fragment -PreContent '<a id="esxi-free-pool"></a><h3>Free Pool Health</h3>' -As Table -PostContent '<p>No issues found.</p>'
                    } else {
                        $allConfigurationObject = $allConfigurationObject | ConvertTo-Html -Fragment -PreContent '<a id="esxi-free-pool"></a><h3>Free Pool Health</h3>' -As Table
                    }
                } else {
                    $allConfigurationObject = $allConfigurationObject | ConvertTo-Html -Fragment -PreContent '<a id="esxi-free-pool"></a><h3>Free Pool Health</h3>' -As Table -PostContent '<p>No ESXi hosts present in the free pool.</p>'
                }

                $allConfigurationObject = Convert-CssClass -htmldata $allConfigurationObject
                $allConfigurationObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-SddcManagerFreePool

Function Request-SddcManagerFreePool {
    <#
        .SYNOPSIS
        Returns the status of the ESXi hosts in the free pool.

        .DESCRIPTION
        The Request-SddcManagerFreePool cmdlet returns status of the ESXi hosts in the free pool. The cmdlet connects
        to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity and authentication is possible to the SDDC Manager instance
        - Gathers the details for the ESXi hosts in the free pool

        .EXAMPLE
        Request-SddcManagerFreePool -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
        This example will return the ESXi hosts in the free pool managed by SDDC Manager for a workload domain.

        .EXAMPLE
        Request-SddcManagerFreePool -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -failureOnly
        This example will return the ESXi hosts in the free pool managed by SDDC Manager for a workload domain but only reports issues.
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
                $versionList = New-Object System.Collections.ArrayList
                $customObject = New-Object System.Collections.ArrayList
                $assignedEsxiHost = (Get-VCFHost | Where-Object {$_.status -eq "ASSIGNED"})
                foreach ($esxiHost in $assignedEsxiHost) {
                    if ($versionList -notcontains $esxiHost.esxiVersion ) {
                        $versionList += $esxiHost.esxiVersion
                    }
                }

                $unassignedEsxiHosts = (Get-VCFHost | Where-Object {$_.status -eq "UNASSIGNED_USEABLE"})
                foreach ($esxiHost in $unassignedEsxiHosts) {
                    if ($esxiHost.status -eq "UNASSIGNED_USEABLE") {
                        foreach ($version in $versionList) {
                            if ($esxiHost.esxiVersion -eq $version) {
                                $alert = "GREEN"
                                $message = "Current ESXi Host version $($esxiHost.esxiVersion) matches supported version(s)."
                            } else {
                                $alert = "RED"
                                $message = "Current ESXi Host version $($esxiHost.esxiVersion), does not match supported version(s)."
                            }
                        }
                        $elementObject = New-Object -TypeName psobject
                        $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue 'ESXi Version'
                        $elementObject | Add-Member -NotePropertyName 'ESXi FQDN' -NotePropertyValue $esxiHost.fqdn
                        $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
                        $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $message
                        if ($PsBoundParameters.ContainsKey('failureOnly')) {
                            if ($alert -eq "RED") {
                                $customObject += $elementObject
                            }
                        } else {
                            $customObject += $elementObject
                        }

                        $esxiCreds = Get-VCFCredential | Where-Object {$_.resource.resourceName -eq $esxiHost.fqdn -and $_.username -eq "root"}
                        Connect-VIServer -Server $esxiHost.fqdn -User $esxiCreds.username -Password $esxiCreds.password | Out-Null
                        $licenseManager = Get-View -Id "LicenseManager-ha-license-manager"
                        foreach ($properties in $licenseManager.Evaluation.Properties) {
                            if ($properties.key -eq "expirationDate") {
                                $expirationDate = $properties.value
                                $expiryDate = [math]::Ceiling((([DateTime]$expirationDate) - (Get-Date)).TotalDays)
                            } elseif ($properties.key -eq "diagnostic") {
                                $expiryDate = 0
                            }
                        }
                        if ($expiryDate -gt "0") {
                            $alert = "GREEN"
                            $message = "No expired license running on the host."
                        } else {
                            $alert = "RED"
                            $message = "License installed on the ESXi host has expired."
                        }
                        $elementObject = New-Object -TypeName psobject
                        $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue 'ESXi License'
                        $elementObject | Add-Member -NotePropertyName 'ESXi FQDN' -NotePropertyValue $esxiHost.fqdn
                        $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
                        $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $message
                        Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                        if ($PsBoundParameters.ContainsKey('failureOnly')) {
                            if ($alert -eq "RED") {
                                $customObject += $elementObject
                            }
                        } else {
                            $customObject += $elementObject
                        }
                    }
                }
                $customObject | Sort-Object Component, 'ESXi FQDN'
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-SddcManagerFreePool

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
                } else {
                    if ($PsBoundParameters.ContainsKey('allDomains')) {
                        foreach ($domain in $allWorkloadDomains ) {
                            $esxiSystemAlert = Request-EsxiAlert -server $server -user $user -pass $pass $domain.name; $allAlertObject += $esxiSystemAlert
                        }
                    } else {
                        $esxiSystemAlert = Request-EsxiAlert -server $server -user $user -pass $pass -domain $workloadDomain; $allAlertObject += $esxiSystemAlert
                    }
                }

                if ($allAlertObject.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $allAlertObject = $allAlertObject | Sort-Object Component, Resource, Domain | ConvertTo-Html -Fragment -PreContent '<a id="alert-esxi"></a><h3>ESXi Host Alert</h3>' -PostContent '<p>No alerts found.</p>'
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
                    $allAlertObject = $allAlertObject | Sort-Object Component, Resource, Domain | ConvertTo-Html -Fragment -PreContent '<a id="alert-nsx"></a><h3>NSX-T Data Center Alert</h3>' -PostContent '<p>No alerts found.</p>'
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

                if ($allAlertObject.Count -eq 0) { $addNoIssues = $true  }
                if ($addNoIssues) {
                    $allAlertObject = $allAlertObject | Sort-Object Component, Resource, Domain | ConvertTo-Html -Fragment -PreContent '<a id="alert-vcenter"></a><h3>vCenter Server Alert</h3>' -PostContent '<p>No alerts found.</p>'
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

                if ($allAlertObject.Count -eq 0) { $addNoIssues = $true }
                if ($addNoIssues) {
                    $allAlertObject = $allAlertObject | Sort-Object Component, Resource, Domain | ConvertTo-Html -Fragment -PreContent '<a id="alert-vsan"></a><h3>vSAN Alert</h3>' -PostContent '<p>No alerts found.</p>'
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
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
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
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
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
                        $customObject | Sort-Object Component, Resource, Domain, Cluster, Alert
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
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateSet("hostOnly","vsanOnly")][ValidateNotNullOrEmpty()] [String]$filterOut,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
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
                                } else {
                                    $customObject += $elementObject
                                }
                            }

                        }
                        Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                        $customObject | Sort-Object Component, Resource, Domain, 'Entity Type', Alert
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
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$domain,
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
                        $customObject | Sort-Object Component, Resource, Domain, Entity, Alert
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

Function Publish-ClusterConfiguration {
    <#
        .SYNOPSIS
        Publish cluster configuration information in HTML format.

        .DESCRIPTION
        The Publish-ClusterConfiguration cmdlet returns cluster configuration information in HTML format.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Server instance
        - Validates the authentication to vCenter Server with credentials from SDDC Manager
        - Publishes information

        .EXAMPLE
        Publish-ClusterConfiguration -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will return cluster configuration from all clusters in vCenter Server managed by SDDC Manager for a all workload domains.

        .EXAMPLE
        Publish-ClusterConfiguration -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will return cluster configuration from all clusters in vCenter Server managed by SDDC Manager for a workload domain names sfo-w01.
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
                $allConfigurationObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('allDomains')) {
                    $allWorkloadDomains = Get-VCFWorkloadDomain
                    foreach ($domain in $allWorkloadDomains ) {
                        $clusterConfiguration = Request-ClusterConfiguration -server  $server -user $user -pass $pass -domain $domain.name;
                        $allConfigurationObject += $clusterConfiguration
                    }
                } else {
                    $clusterConfiguration = Request-ClusterConfiguration -server  $server -user $user -pass $pass -domain $workloadDomain; $allConfigurationObject += $clusterConfiguration
                }
                $allConfigurationObject = $allConfigurationObject | Sort-Object Cluster | ConvertTo-Html -Fragment -PreContent '<a id="cluster-config"></a><h3>Cluster Configuration</h3>' -As Table
                $allConfigurationObject = Convert-CssClass -htmldata $allConfigurationObject
                $allConfigurationObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-ClusterConfiguration

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

Function Request-ClusterConfiguration {
    <#
		.SYNOPSIS
        Gets cluster configuration from a vCenter Server instance.

        .DESCRIPTION
        The Request-ClusterConfiguration cmdlets gets the cluster configuration for a vCenter Server instance. The
        cmdlet  connects to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Gathers the cluster details from vCenter Server

        .EXAMPLE
        Request-ClusterConfiguration -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-m01
        This example gets the cluster configuration for a vCenter Server instance based on the Workload Domain provided.
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
                            $allClustersObject = New-Object System.Collections.ArrayList
                            $allClusters = Get-Cluster -Server $vcfVcenterDetails.fqdn
                            foreach ($cluster in $allClusters) {
                                $haStatus = if ($cluster.HAEnabled -eq "True") { "Enabled" } else { "Disabled" }
                                $drsStatus = if ($cluster.DrsEnabled -eq "True") { "Enabled" } else { "Disabled" }
                                $evcStatus = if ($null -eq $cluster.EVCMode) { "Disabled" } else { $cluster.EVCMode }
                                $clusterAdvancedSettings = Get-AdvancedSetting -Entity (Get-Cluster -Name $cluster) | Select-Object Name, Value
                                $settingsObject = New-Object System.Collections.ArrayList
                                foreach ($AdvancedSetting in $clusterAdvancedSettings) {
                                    $settingsObject += "$($AdvancedSetting.Name) : $($AdvancedSetting.Value)"
                                }

                                $customObject = New-Object -TypeName psobject
                                $customObject | Add-Member -notepropertyname "Cluster Name" -notepropertyvalue $cluster.Name
                                $customObject | Add-Member -notepropertyname "vSphere HA" -notepropertyvalue $haStatus
                                $customObject | Add-Member -notepropertyname "vSphere DRS" -notepropertyvalue $drsStatus
                                $customObject | Add-Member -notepropertyname "vSphere DRS Mode" -notepropertyvalue $cluster.DrsAutomationLevel
                                $customObject | Add-Member -notepropertyname "vSphere EVC" -notepropertyvalue $evcStatus
                                $customObject | Add-Member -Type NoteProperty -Name "Advanced Settings" -Value ($settingsObject -join ':-: ')
                                $allClustersObject += $customObject
                            }
                            $allClustersObject
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
Export-ModuleMember -Function Request-ClusterConfiguration

Function Publish-ClusterDrsRule {
    <#
        .SYNOPSIS
        Publish cluster DRS rule information in HTML format.

        .DESCRIPTION
        The Publish-ClusterDrsRule cmdlet returns cluster DRS rule information in HTML format.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Server instance
        - Validates the authentication to vCenter Server with credentials from SDDC Manager
        - Publishes information

        .EXAMPLE
        Publish-ClusterDrsRule -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will return cluster DRS rules from all clusters in vCenter Server managed by SDDC Manager for a all workload domains.

        .EXAMPLE
        Publish-ClusterDrsRule -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will return cluster DRS rules from all clusters in vCenter Server managed by SDDC Manager for a workload domain names sfo-w01.
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
                $allConfigurationObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('allDomains')) {
                    $allWorkloadDomains = Get-VCFWorkloadDomain
                    foreach ($domain in $allWorkloadDomains ) {
                        $drsRulesConfig = Request-ClusterDrsRule -server  $server -user $user -pass $pass -domain $domain.name; $allConfigurationObject += $drsRulesConfig
                    }
                } else {
                    $drsRulesConfig = Request-ClusterDrsRule -server  $server -user $user -pass $pass -domain $workloadDomain; $allConfigurationObject += $drsRulesConfig
                }

                if ($allConfigurationObject.Count -ne 0) {
                    $allConfigurationObject = $allConfigurationObject | Sort-Object Cluster, 'VM/Host Rule' | ConvertTo-Html -Fragment -PreContent '<a id="cluster-drs-rules"></a><h3>vSphere DRS Rules</h3>' -As Table
                    $allConfigurationObject = Convert-CssClass -htmldata $allConfigurationObject
                } else {
                    $allConfigurationObject = $allConfigurationObject | Sort-Object Cluster, 'VM/Host Rule' | ConvertTo-Html -Fragment -PreContent '<a id="cluster-drs-rules"></a><h3>vSphere DRS Rules</h3>' -PostContent '<p>No DRS Rules found.</p>'
                }
                $allConfigurationObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-ClusterDrsRule

Function Request-ClusterDrsRule {
    <#
		.SYNOPSIS
        Gets cluster DRS rules from a vCenter Server instance.

        .DESCRIPTION
        The Request-ClusterDrsRule cmdlets gets the cluster DRS rules for a vCenter Server instance. The
        cmdlet  connects to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Gathers the cluster DRS rules from vCenter Server

        .EXAMPLE
        Request-ClusterDrsRule -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-m01
        This example gets the cluster DRS rules for a vCenter Server instance based on the Workload Domain provided.
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
                            $allClustersObject = New-Object System.Collections.ArrayList
                            $allClusters = Get-Cluster -Server $vcfVcenterDetails.fqdn
                            foreach ($cluster in $allClusters) {
                                $drsRules = Get-Cluster -Name $cluster -Server $vcfVcenterDetails.fqdn | Get-DrsRule
                                foreach ($drsRule in $drsRules) {
                                    $vmList = New-Object System.Collections.ArrayList
                                    foreach ($vm in $drsRule.VMIDS) {
                                        $vmName = (Get-VM -Id $vm -Server $vcfVcenterDetails.fqdn).Name
                                        $vmList += $vmName
                                    }

                                    $customObject = New-Object -TypeName psobject
                                    $customObject | Add-Member -notepropertyname "Cluster" -notepropertyvalue $cluster.Name
                                    $customObject | Add-Member -notepropertyname "VM/Host Rule" -notepropertyvalue $drsRule.Name
                                    $customObject | Add-Member -notepropertyname "Enabled" -notepropertyvalue $drsRule.Enabled
                                    $customObject | Add-Member -notepropertyname "Type" -notepropertyvalue $drsRule.Type
                                    $customObject | Add-Member -notepropertyname "VMs" -notepropertyvalue ($vmList -join ':-: ')
                                    $allClustersObject += $customObject
                                }
                            }
                            $allClustersObject
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
Export-ModuleMember -Function Request-ClusterDrsRule

Function Publish-ResourcePool {
    <#
        .SYNOPSIS
        Publish resource pool information in HTML format.

        .DESCRIPTION
        The Publish-ResourcePool cmdlet returns resource pool information in HTML format.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Server instance
        - Validates the authentication to vCenter Server with credentials from SDDC Manager
        - Publishes resource pool information

        .EXAMPLE
        Publish-ResourcePool -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will return resource pool details from all clusters in vCenter Server managed by SDDC Manager for a all workload domains.

        .EXAMPLE
        Publish-ResourcePool -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will return resource pool details from all clusters in vCenter Server managed by SDDC Manager for a workload domain names sfo-w01.
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
                $allConfigurationObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('allDomains')) {
                    $allWorkloadDomains = Get-VCFWorkloadDomain
                    foreach ($domain in $allWorkloadDomains ) {
                        $resourcePoolConfig = Request-ResourcePool -server  $server -user $user -pass $pass -domain $domain.name; $allConfigurationObject += $resourcePoolConfig
                    }
                } else {
                    $resourcePoolConfig = Request-ResourcePool -server  $server -user $user -pass $pass -domain $workloadDomain; $allConfigurationObject += $resourcePoolConfig
                }
                $allConfigurationObject = $allConfigurationObject | Sort-Object Cluster, 'Resource Pool' | ConvertTo-Html -Fragment -PreContent '<a id="cluster-resource-pools"></a><h3>Resource Pools</h3>' -As Table
                $allConfigurationObject = Convert-CssClass -htmldata $allConfigurationObject
                $allConfigurationObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-ResourcePool

Function Request-ResourcePool {
    <#
		.SYNOPSIS
        Gets resource pool details from a vCenter Server instance.

        .DESCRIPTION
        The Request-ResourcePool cmdlets gets the resource pool details for a vCenter Server instance. The cmdlet
        connects to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Gathers the resource pool details from vCenter Server

        .EXAMPLE
        Request-ResourcePool -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-m01
        This example gets the resource pool details for a vCenter Server instance based on the Workload Domain provided.
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
                            $allClustersObject = New-Object System.Collections.ArrayList
                            $allClusters = Get-Cluster -Server $vcfVcenterDetails.fqdn
                            foreach ($cluster in $allClusters) {
                                $resourcePools = Get-ResourcePool -Server $vcfVcenterDetails.fqdn
                                foreach ($resourcePool in $resourcePools) {
                                    if ($resourcePool.Parent -ne $cluster) {
                                        $customObject = New-Object -TypeName psobject
                                        $customObject | Add-Member -notepropertyname "Cluster" -notepropertyvalue $cluster.Name
                                        $customObject | Add-Member -notepropertyname "Resource Pool" -notepropertyvalue $resourcePool.Name
                                        $customObject | Add-Member -notepropertyname "CPU Share Level" -notepropertyvalue $resourcePool.CpuSharesLevel
                                        $customObject | Add-Member -notepropertyname "CPU Expandable" -notepropertyvalue $resourcePool.CpuExpandableReservation
                                        $customObject | Add-Member -notepropertyname "Memory Share Level" -notepropertyvalue $resourcePool.MemSharesLevel
                                        $customObject | Add-Member -notepropertyname "Memory Expandable" -notepropertyvalue $resourcePool.MemExpandableReservation
                                        $allClustersObject += $customObject
                                    }
                                }
                            }
                            $allClustersObject
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
Export-ModuleMember -Function Request-ResourcePool

Function Publish-VmOverride {
    <#
        .SYNOPSIS
        Publish VM Override information in HTML format.

        .DESCRIPTION
        The Publish-VmOverride cmdlet returns VM Override information in HTML format.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Server instance
        - Validates the authentication to vCenter Server with credentials from SDDC Manager
        - Publishes information

        .EXAMPLE
        Publish-VmOverride -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will return VM Override details from all clusters in vCenter Server managed by SDDC Manager for a all workload domains.

        .EXAMPLE
        Publish-VmOverride -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will return VM Override details from all clusters in vCenter Server managed by SDDC Manager for a workload domain names sfo-w01.
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
                $allConfigurationObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('allDomains')) {
                    $allWorkloadDomains = Get-VCFWorkloadDomain
                    foreach ($domain in $allWorkloadDomains ) {
                        $vmOverRideConfig = Request-VmOverride -server  $server -user $user -pass $pass -domain $domain.name; $allConfigurationObject += $vmOverRideConfig
                    }
                } else {
                    $vmOverRideConfig = Request-VmOverride -server  $server -user $user -pass $pass -domain $workloadDomain; $allConfigurationObject += $vmOverRideConfig
                }
                $allConfigurationObject = $allConfigurationObject | Sort-Object Cluster, 'DRS Automation Level', 'VM Name' | ConvertTo-Html -Fragment -PreContent '<a id="cluster-overrides"></a><h3>VM Overrides</h3>' -As Table
                $allConfigurationObject = Convert-CssClass -htmldata $allConfigurationObject
                $allConfigurationObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-VmOverride

Function Request-VmOverride {
    <#
		.SYNOPSIS
        Gets VM Override setting from a vCenter Server instance.

        .DESCRIPTION
        The Request-VmOverride cmdlets gets VM Override setting for a vCenter Server instance. The cmdlet connects to
        SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Gathers the VM Override settings from vCenter Server

        .EXAMPLE
        Request-VmOverride -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-m01
        This example gets the VM Override setting for a vCenter Server instance based on the Workload Domain provided.
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
                            $allClustersObject = New-Object System.Collections.ArrayList
                            $allClusters = Get-Cluster -Server $vcfVcenterDetails.fqdn
                            foreach ($cluster in $allClusters) {
                                $allVms = Get-VM -Server $vcfVcenterDetails.fqdn | Select-Object Name,DrsAutomationLevel
                                foreach ($vm in $allVms) {
                                    $customObject = New-Object -TypeName psobject
                                    $customObject | Add-Member -notepropertyname "Cluster" -notepropertyvalue $cluster.Name
                                    $customObject | Add-Member -notepropertyname "VM Name" -notepropertyvalue $vm.Name
                                    $customObject | Add-Member -notepropertyname "DRS Automation Level" -notepropertyvalue ($vm.DrsAutomationLevel -creplace '.(?![a-z])','$& ' )
                                    $allClustersObject += $customObject
                                }
                            }
                            $allClustersObject
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
Export-ModuleMember -Function Request-VmOverride

Function Publish-VirtualNetwork {
    <#
        .SYNOPSIS
        Publish vSphere virtual networking information in HTML format.

        .DESCRIPTION
        The Publish-VirtualNetwork cmdlet returns vSphere virtual networking information in HTML format.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Server instance
        - Validates the authentication to vCenter Server with credentials from SDDC Manager
        - Publishes information

        .EXAMPLE
        Publish-VirtualNetwork -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will return vSphere virtual networking details from all clusters in vCenter Server managed by SDDC Manager for a all workload domains.

        .EXAMPLE
        Publish-VirtualNetwork -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will return vSphere virtual networking details from all clusters in vCenter Server managed by SDDC Manager for a workload domain names sfo-w01.
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
                $allConfigurationObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('allDomains')) {
                    $allWorkloadDomains = Get-VCFWorkloadDomain
                    foreach ($domain in $allWorkloadDomains ) {
                        $virtualNetworkConfig = Request-VirtualNetwork -server  $server -user $user -pass $pass -domain $domain.name; $allConfigurationObject += $virtualNetworkConfig
                    }
                } else {
                    $virtualNetworkConfig = Request-VirtualNetwork -server  $server -user $user -pass $pass -domain $workloadDomain; $allConfigurationObject += $virtualNetworkConfig
                }
                $allConfigurationObject = $allConfigurationObject | Sort-Object Cluster, 'vSphere Distributed Switch' | ConvertTo-Html -Fragment -PreContent '<a id="cluster-networks"></a><h3>Virtual Networks</h3>' -As Table
                $allConfigurationObject = Convert-CssClass -htmldata $allConfigurationObject
                $allConfigurationObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-VirtualNetwork

Function Request-VirtualNetwork {
    <#
		.SYNOPSIS
        Gets vSphere virtual networking configuration from a vCenter Server instance.

        .DESCRIPTION
        The Request-VirtualNetwork cmdlets gets vSphere virtual networking configuration for a vCenter Server instance.
        The cmdlet connects to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Gathers the vSphere virtual networking configuration from vCenter Server

        .EXAMPLE
        Request-VirtualNetwork -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-m01
        This example gets the vSphere virtual networking configurationfor a vCenter Server instance based on the Workload Domain provided.
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
                            $allClustersObject = New-Object System.Collections.ArrayList
                            $allClusters = Get-Cluster -Server $vcfVcenterDetails.fqdn
                            foreach ($cluster in $allClusters) {
                                $allVds = Get-VDSwitch -Server $vcfVcenterDetails.fqdn
                                foreach ($vds in $allVds) {
                                    $allPortgroups = Get-VDPortgroup -Server $vcfVcenterDetails.fqdn | Where-Object {$_.VDSwitch -eq $vds}
                                    $settingsObject = New-Object System.Collections.ArrayList
                                    foreach ($portgroup in $allPortgroups) {
                                        $settingsObject += "$($portgroup.Name) : $($portgroup.PortBinding)"
                                    }
                                    $customObject = New-Object -TypeName psobject
                                    $customObject | Add-Member -notepropertyname "Cluster" -notepropertyvalue $cluster.Name
                                    $customObject | Add-Member -notepropertyname "vSphere Distributed Switch" -notepropertyvalue $vds.Name
                                    $customObject | Add-Member -notepropertyname "Switch Version" -notepropertyvalue $vds.Version
                                    $customObject | Add-Member -notepropertyname "MTU" -notepropertyvalue $vds.Mtu
                                    $customObject | Add-Member -notepropertyname "Portgroups" -notepropertyvalue ($settingsObject -join ':-: ')
                                    $allClustersObject += $customObject
                                }
                            }
                            $allClustersObject
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
Export-ModuleMember -Function Request-VirtualNetwork

Function Publish-EsxiSecurityConfiguration {
    <#
        .SYNOPSIS
        Publish ESXi security information in HTML format.

        .DESCRIPTION
        The Publish-EsxiSecurityConfiguration cmdlet returns ESXi security information in HTML format.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the vCenter Server instance
        - Validates the authentication to vCenter Server with credentials from SDDC Manager
        - Publishes information

        .EXAMPLE
        Publish-EsxiSecurityConfiguration -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
        This example will return ESXi security details from all clusters in vCenter Server managed by SDDC Manager for a all workload domains.

        .EXAMPLE
        Publish-EsxiSecurityConfiguration -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
        This example will return ESXi security details from all clusters in vCenter Server managed by SDDC Manager for a workload domain names sfo-w01.
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
                $allConfigurationObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('allDomains')) {
                    $allWorkloadDomains = Get-VCFWorkloadDomain
                    foreach ($domain in $allWorkloadDomains ) {
                        $esxiSecurityConfig = Request-EsxiSecurityConfiguration -server  $server -user $user -pass $pass -domain $domain.name; $allConfigurationObject += $esxiSecurityConfig
                    }
                } else {
                    $esxiSecurityConfig = Request-EsxiSecurityConfiguration -server  $server -user $user -pass $pass -domain $workloadDomain; $allConfigurationObject += $esxiSecurityConfig
                }
                $allConfigurationObject = $allConfigurationObject | Sort-Object Cluster, 'ESXi FQDN' | ConvertTo-Html -Fragment -PreContent '<a id="esxi-security"></a><h3>Security Configuration</h3>' -As Table
                $allConfigurationObject = Convert-CssClass -htmldata $allConfigurationObject
                $allConfigurationObject
            }
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-EsxiSecurityConfiguration

Function Request-EsxiSecurityConfiguration {
    <#
		.SYNOPSIS
        Gets ESXi security configuration from a vCenter Server instance.

        .DESCRIPTION
        The Request-EsxiSecurityConfiguration cmdlets gets ESXi security configuration for a vCenter Server instance.
        The cmdlet connects to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Gathers the ESXi security configuration from vCenter Server

        .EXAMPLE
        Request-EsxiSecurityConfiguration -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-m01
        This example gets the ESXi security configurationfor a vCenter Server instance based on the Workload Domain provided.
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
                            $allClustersObject = New-Object System.Collections.ArrayList
                            $allClusters = Get-Cluster -Server $vcfVcenterDetails.fqdn
                            foreach ($cluster in $allClusters) {
                                $allHosts = Get-VMHost -Server $vcfVcenterDetails.fqdn
                                foreach ($esxHost in $allHosts) {
                                    $lockdownStatus = if ($esxHost.ExtensionData.Config.LockdownMode -eq "lockdownDisabled" ) { "False" } else { "True" }
                                    $customObject = New-Object -TypeName psobject
                                    $customObject | Add-Member -notepropertyname "Cluster" -notepropertyvalue $cluster.Name
                                    $customObject | Add-Member -notepropertyname "ESXi FQDN" -notepropertyvalue $esxHost.Name
                                    $customObject | Add-Member -notepropertyname "SSH Enabled" -notepropertyvalue (Get-VMHostService -VMHost $esxHost | Where-Object { $_.key -eq 'TSM-SSH' }).Running
                                    $customObject | Add-Member -notepropertyname "Lockdown Enabled" -notepropertyvalue $lockdownStatus
                                    $allClustersObject += $customObject
                                }
                            }
                            $allClustersObject
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
Export-ModuleMember -Function Request-EsxiSecurityConfiguration

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
                } else {
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
                } else {
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
                        Request-VcenterApiToken -fqdn $vcfVcenterDetails.fqdn -username $vcfVcenterDetails.ssoAdmin -password $vcfVcenterDetails.ssoAdminPass | Out-Null
                        $customObject = New-Object System.Collections.ArrayList
                        $rootPasswordExpiry = Get-VCRootPasswordExpiry
                        $customObject = New-Object -TypeName psobject
                        $customObject | Add-Member -notepropertyname "vCenter Server FQDN" -notepropertyvalue $vcfVcenterDetails.fqdn
                        $customObject | Add-Member -notepropertyname "Lifetime (days)" -notepropertyvalue $rootPasswordExpiry.max_days_between_password_change
                        $customObject | Add-Member -notepropertyname "Warning (days)" -notepropertyvalue $rootPasswordExpiry.warn_days_before_password_expiration
                        $customObject | Add-Member -notepropertyname "Email" -notepropertyvalue $rootPasswordExpiry.email
                        $customObject | Add-Member -notepropertyname "Enabled" -notepropertyvalue $rootPasswordExpiry.enabled
                        $customObject | Add-Member -notepropertyname "Expires" -notepropertyvalue $rootPasswordExpiry.password_expires_at
                    }
                    $customObject | Sort-Object 'vCenter Server FQDN'
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
                        if (Test-vSphereConnection -server $($vcfVcenterDetails.fqdn)) {
                            if (Test-vSphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                                $passwordPolicy = Invoke-GetLocalAccountsGlobalPolicy
                                $customObject = New-Object -TypeName psobject
                                $customObject | Add-Member -notepropertyname "vCenter Server FQDN" -notepropertyvalue $vcfVcenterDetails.fqdn
                                $customObject | Add-Member -notepropertyname "Lifetime (max days)" -notepropertyvalue $passwordPolicy.max_days
                                $customObject | Add-Member -notepropertyname "Lifetime (min days)" -notepropertyvalue $passwordPolicy.min_days
                                $customObject | Add-Member -notepropertyname "Warning (days)" -notepropertyvalue $passwordPolicy.warn_days
                            }
                            Disconnect-VIServer -Server $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue | Out-Null
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
                $allNsxtEdgePasswordPolicyObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('allDomains')) {
                    $allWorkloadDomains = Get-VCFWorkloadDomain
                    foreach ($domain in $allWorkloadDomains ) {
                        $nsxtManagerPasswordPolicy = Request-NsxtManagerPasswordPolicy -server $server -user $user -pass $pass -domain $domain.name; $allNsxtManagerPasswordPolicyObject += $nsxtManagerPasswordPolicy
                        $nsxtEdgePasswordPolicy = Request-NsxtEdgePasswordPolicy -server $server -user $user -pass $pass -domain $domain.name; $allNsxtEdgePasswordPolicyObject += $nsxtEdgePasswordPolicy
                    }
                }
                else {
                    $nsxtManagerPasswordPolicy = Request-NsxtManagerPasswordPolicy -server $server -user $user -pass $pass -domain $workloadDomain; $allNsxtManagerPasswordPolicyObject += $nsxtManagerPasswordPolicy
                    $nsxtEdgePasswordPolicy = Request-NsxtEdgePasswordPolicy -server $server -user $user -pass $pass -domain $workloadDomain; $allNsxtEdgePasswordPolicyObject += $nsxtEdgePasswordPolicy
                }

                $allNsxtManagerPasswordPolicyObject = $allNsxtManagerPasswordPolicyObject | Sort-Object Cluster, 'NSX Manager FQDN' | ConvertTo-Html -Fragment -PreContent '<a id="policy-password-manager"></a><h3>NSX Manager Password Policy</h3>' -As Table
                $allNsxtManagerPasswordPolicyObject = Convert-CssClass -htmldata $allNsxtManagerPasswordPolicyObject
                $allNsxtPolicyObject += $allNsxtManagerPasswordPolicyObject

                if ($allNsxtEdgePasswordPolicyObject.Count -gt 0) {
                    $allNsxtEdgePasswordPolicyObject = $allNsxtEdgePasswordPolicyObject | Sort-Object Cluster, 'NSX Edge' | ConvertTo-Html -Fragment -PreContent '<a id="policy-password-edge"></a><h3>NSX Edge Password Policy</h3>' -As Table
                    $allNsxtEdgePasswordPolicyObject = Convert-CssClass -htmldata $allNsxtEdgePasswordPolicyObject
                } else {
                    $allNsxtEdgePasswordPolicyObject = $allNsxtEdgePasswordPolicyObject | ConvertTo-Html -Fragment -PreContent '<a id="policy-password-edge"></a><h3>NSX Edge Password Policy</h3>' -PostContent '<p>No NSX Edge Node(s) present.</p>' -As Table
                }
                $allNsxtPolicyObject += $allNsxtEdgePasswordPolicyObject
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

        .EXAMPLE
        Publish-VcfSystemOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -anonymized
        This example will return system overview report for SDDC Manager for a all workload domains, but with anonymized data.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$anonymized
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $allOverviewObject = New-Object System.Collections.ArrayList
                if ($PsBoundParameters.ContainsKey('anonymized')) {
                    $vcfOverview = Request-VcfOverview -server $server -user $user -pass $pass -anonymized
                    $hardwareOverview = Request-HardwareOverview -server $server -user $user -pass $pass
                    $vcenterOverview = Request-VcenterOverview -server $server -user $user -pass $pass -anonymized
                    $esxiOverview = Request-EsxiOverview -server $server -user $user -pass $pass -anonymized
                    $clusterOverview = Request-ClusterOverview -server $server -user $user -pass $pass -anonymized
                    $networkingOverview = Request-NetworkOverview -server $server -user $user -pass $pass -anonymized
                    $vrealizeOverview = Request-VrealizeOverview -server $server -user $user -pass $pass -anonymized
                    $vvsOverview = Request-ValidatedSolutionOverview -server $server -user $user -pass $pass
                } else {
                    $vcfOverview = Request-VcfOverview -server $server -user $user -pass $pass
                    $hardwareOverview = Request-HardwareOverview -server $server -user $user -pass $pass
                    $vcenterOverview = Request-VcenterOverview -server $server -user $user -pass $pass
                    $clusterOverview = Request-ClusterOverview -server $server -user $user -pass $pass
                    $esxiOverview = Request-EsxiOverview -server $server -user $user -pass $pass
                    $networkingOverview = Request-NetworkOverview -server $server -user $user -pass $pass
                    $vrealizeOverview = Request-VrealizeOverview -server $server -user $user -pass $pass
                    $vvsOverview = Request-ValidatedSolutionOverview -server $server -user $user -pass $pass
                }

                $vcfOverview = $vcfOverview | ConvertTo-Html -Fragment -PreContent '<h4>VMware Cloud Foundation Overview</h4>'
                $vcfOverview = Convert-CssClass -htmldata $vcfOverview
                $hardwareOverview = $hardwareOverview | ConvertTo-Html -Fragment -PreContent '<h4>Hardware Overview</h4>'
                $hardwareOverview = Convert-CssClass -htmldata $hardwareOverview
                $vcenterOverview = $vcenterOverview | ConvertTo-Html -Fragment -PreContent '<h4>vCenter Server Overview</h4>' -As Table
                $vcenterOverview = Convert-CssClass -htmldata $vcenterOverview
                $clusterOverview = $clusterOverview | ConvertTo-Html -Fragment -PreContent '<h4>vSphere Cluster Overview</h4>'
                $clusterOverview = Convert-CssClass -htmldata $clusterOverview
                $esxiOverview = $esxiOverview | ConvertTo-Html -Fragment -PreContent '<h4>ESXi Host Overview</h4>'
                $esxiOverview = Convert-CssClass -htmldata $esxiOverview
                $networkingOverview = $networkingOverview | ConvertTo-Html -Fragment -PreContent '<h4>Networking Overview</h4>'
                $networkingOverview = Convert-CssClass -htmldata $networkingOverview
                if ($vrealizeOverview) {
                    $vrealizeOverview = $vrealizeOverview | ConvertTo-Html -Fragment -PreContent '<h4>vRealize Suite Overview</h4>'
                    $vrealizeOverview = Convert-CssClass -htmldata $vrealizeOverview
                } else {
                    $vrealizeOverview = $vrealizeOverview | ConvertTo-Html -Fragment -PreContent '<h4>vRealize Suite Overview</h4>' -PostContent '<p>No vRealize Suite Installed.</p>'
                }
                $vvsOverview = $vvsOverview | ConvertTo-Html -Fragment -PreContent '<h4>VMware Validated Solutions Overview</h4>'
                $vvsOverview = Convert-CssClass -htmldata $vvsOverview

                $allOverviewObject += $vcfOverview
                $allOverviewObject += $hardwareOverview
                $allOverviewObject += $vcenterOverview
                $allOverviewObject += $clusterOverview
                $allOverviewObject += $networkingOverview
                $allOverviewObject += $vrealizeOverview
                $allOverviewObject += $vvsOverview
                $allOverviewObject += $esxiOverview
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

        .EXAMPLE
        Request-VcfOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -anonymized
        This example will return an overview of the SDDC Manager instance, but will anonymize the output.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$anonymized
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT)) { # Gather VCF Architecture
                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            $vcfArchitecture = (Get-AdvancedSetting -Name "config.SDDC.Deployed.Flavor" -Entity $vcfVcenterDetails.fqdn -Server $vcfVcenterDetails.fqdn).value
                            Disconnect-VIServer -Server $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                        }
                    }
                }
                if (Get-VCFDepotCredential) {
                    $depotUser = (Get-VCFDepotCredential).username.ToLower()
                    $depotStatus = ((Get-VCFDepotCredential).message -Split ": ")[-1]
                } else {
                    $depotUser = "Not Configured"
                    $depotStatus = "Not Connected"
                }
                $systemObject = New-Object -TypeName psobject
                if ($PsBoundParameters.ContainsKey('anonymized')) {
                    $systemObject | Add-Member -notepropertyname "SDDC Manager UUID" -notepropertyvalue (Get-VCFManager).id
                } else {
                    $systemObject | Add-Member -notepropertyname "SDDC Manager FQDN" -notepropertyvalue (Get-VCFManager).fqdn
                }
                $systemObject | Add-Member -notepropertyname "Version" -notepropertyvalue (Get-VCFManager).version
                $systemObject | Add-Member -notepropertyname "Architecture" -notepropertyvalue $vcfArchitecture
                $systemObject | Add-Member -notepropertyname "CEIP Status" -notepropertyvalue (Get-Culture).TextInfo.ToTitleCase((Get-VCFCeip).status.ToLower())
                $systemObject | Add-Member -notepropertyname "Customer Connect User" -notepropertyvalue $depotUser
                $systemObject | Add-Member -notepropertyname "Customer Connect Status" -notepropertyvalue $depotStatus
                $systemObject
            }
        }
    }
	Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Request-VcfOverview

Function Request-HardwareOverview {
    <#
        .SYNOPSIS
        Returns Hardware Overview.

        .DESCRIPTION
        The Request-VcfOverview cmdlet returns an overview of the hardware in an SDDC Manager instance.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Collects the hardware details

        .EXAMPLE
        Request-HardwareOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
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
                # Calculate Total VMs Across VCF Instance
                $totalVms = $null
                $totalPoweredOnVms = $null
                $totalPoweredOffVms = $null
                $allWorkloadDomains = Get-VCFWorkloadDomain
                foreach ($domain in $allWorkloadDomains) {
                    if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain.name)) {
                        if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                            if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                                $totalVms += (Get-VM -Server $vcfVcenterDetails.fqdn).Count
                                $totalPoweredOnVms += (Get-VM -Server $vcfVcenterDetails.fqdn | Where-Object {$_.PowerState -eq "PoweredOn"}).Count
                                $totalPoweredOffVms += (Get-VM -Server $vcfVcenterDetails.fqdn | Where-Object {$_.PowerState -eq "PoweredOff"}).Count
                            }
                            Disconnect-VIServer -Server $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                        }
                    }
                }
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

                $customObject = New-Object -TypeName psobject
                $customObject | Add-Member -Type NoteProperty -Name "Hardware OEM" -Value ($harwdareOemObject -join ':-: ')
                $customObject | Add-Member -Type NoteProperty -Name "Hardware Platform" -Value ($harwdareModelObject -join ':-: ')
                $customObject | Add-Member -notepropertyname "CPUs Sockets Deployed" -notepropertyvalue $totalSockets
                $customObject | Add-Member -notepropertyname "Hosts Deployed" -notepropertyvalue (Get-VCFHost).Count
                $customObject | Add-Member -notepropertyname "Workload Domains" -notepropertyvalue (Get-VCFWorkloadDomain | Measure-Object).Count
                $customObject | Add-Member -notepropertyname "Total VMs" -notepropertyvalue $totalVms
                $customObject | Add-Member -notepropertyname "Powered On" -notepropertyvalue $totalPoweredOnVms
                $customObject | Add-Member -notepropertyname "Powered Off" -notepropertyvalue $totalPoweredOffVms
                $customObject
            }
        }
    }
	Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Request-HardwareOverview

Function Request-VcenterOverview {
    <#
        .SYNOPSIS
        Returns overview of vSphere.

        .DESCRIPTION
        The Request-VcenterOverview cmdlet returns an overview of the vSphere environment managed by SDDC Manager.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity and authentication to the SDDC Manager instance
        - Validates that network connectivity and authentication to the vCenter Server instances
        - Collects the vSphere overview detail

        .EXAMPLE
        Request-VcenterOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
        This example will return an overview of the vSphere environment managed by the SDDC Manager instance.

        .EXAMPLE
        Request-VcenterOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -aanonymized
        This example will return an overview of the vSphere environment managed by the SDDC Manager instance, but will anonymize the output.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$anonymized
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
                                if ($PsBoundParameters.ContainsKey('anonymized')) {
                                    $customObject | Add-Member -notepropertyname "vCenter Server UUID" -notepropertyvalue $domain.vcenters.id
                                    $customObject | Add-Member -notepropertyname "vCenter Server Version" -notepropertyvalue (Get-VCFvCenter -id $domain.vcenters.id).version
                                    $customObject | Add-Member -notepropertyname "Domain UUID" -notepropertyvalue $domain.id
                                } else {
                                    $customObject | Add-Member -notepropertyname "vCenter Server FQDN" -notepropertyvalue $domain.vcenters.fqdn
                                    $customObject | Add-Member -notepropertyname "vCenter Server Version" -notepropertyvalue (Get-VCFvCenter -id $domain.vcenters.id).version
                                    $customObject | Add-Member -notepropertyname "Domain Name" -notepropertyvalue $domain.name
                                }
                                $customObject | Add-Member -notepropertyname "Domain Type" -notepropertyvalue $domain.type.ToLower()
                                $customObject | Add-Member -notepropertyname "Total Clusters" -notepropertyvalue (Get-Cluster -Server $vcfVcenterDetails.fqdn).Count
                                $customObject | Add-Member -notepropertyname "Total Hosts" -notepropertyvalue (Get-VMHost -Server $vcfVcenterDetails.fqdn).Count
                                $customObject | Add-Member -notepropertyname "Total VMs" -notepropertyvalue (Get-VM -Server $vcfVcenterDetails.fqdn).Count
                                $customObject | Add-Member -notepropertyname "Powered On" -notepropertyvalue (Get-VM -Server $vcfVcenterDetails.fqdn | Where-Object {$_.PowerState -eq "PoweredOn"}).Count
                                $customObject | Add-Member -notepropertyname "Powered Off" -notepropertyvalue (Get-VM -Server $vcfVcenterDetails.fqdn | Where-Object {$_.PowerState -eq "PoweredOff"}).Count
                                Disconnect-VIServer -Server $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                            }
                        }
                    }
                    $allVsphereObject += $customObject
                }
                $allVsphereObject | Sort-Object 'Domain Type', 'Domain Name'
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

Function Request-EsxiOverview {
    <#
        .SYNOPSIS
        Returns overview of ESXi hosts.

        .DESCRIPTION
        The Request-EsxiOverview cmdlet returns an overview of the ESXi host managed by SDDC Manager.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity and authentication to the SDDC Manager instance
        - Validates that network connectivity and authentication to the vCenter Server instances
        - Collects the ESXi host overview detail

        .EXAMPLE
        Request-EsxiOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
        This example will return an overview of the ESXi hosts managed by the SDDC Manager instance.

        .EXAMPLE
        Request-EsxiOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -anonymized
        This example will return an overview of the ESXi hosts managed by the SDDC Manager instance, but will anonymize the output.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$anonymized
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $allWorkloadDomains = Get-VCFWorkloadDomain
                $allEsxiHostObject = New-Object System.Collections.ArrayList
                foreach ($domain in $allWorkloadDomains) {
                    foreach ($cluster in $domain.clusters) {
                        $allAssignedEsxiHosts = (Get-VCFHost | Where-Object {$_.domain.id -eq $domain.id})
                        foreach ($assignedEsxiHost in $allAssignedEsxiHosts) {
                            $customObject = New-Object -TypeName psobject
                            if ($PsBoundParameters.ContainsKey('anonymized')) {
                                $customObject | Add-Member -notepropertyname "Domain UUID" -notepropertyvalue $domain.id
                                $customObject | Add-Member -notepropertyname "Cluster UUID" -notepropertyvalue $cluster.id
                                $customObject | Add-Member -notepropertyname "ESXi Host UUID" -notepropertyvalue $assignedEsxiHost.id
                                $customObject | Add-Member -notepropertyname "ESXi Host Version" -notepropertyvalue $assignedEsxiHost.esxiVersion
                                $customObject | Add-Member -notepropertyname "Hardware OEM" -notepropertyvalue $assignedEsxiHost.hardwareVendor
                                $customObject | Add-Member -notepropertyname "Hardware Platform" -notepropertyvalue $assignedEsxiHost.hardwareModel
                                $customObject | Add-Member -notepropertyname "CPU Sockets" -notepropertyvalue $assignedEsxiHost.cpu.cpuCores.Count
                                $customObject | Add-Member -notepropertyname "CPU Cores" -notepropertyvalue $assignedEsxiHost.cpu.Cores
                                $customObject | Add-Member -notepropertyname "Memory (GB)" -notepropertyvalue ([Math]::round(($assignedEsxiHost.memory.totalCapacityMB) / 1024))
                                $customObject | Add-Member -notepropertyname "Status" -notepropertyvalue $assignedEsxiHost.status
                            } else {
                                $customObject | Add-Member -notepropertyname "Domain Name" -notepropertyvalue $domain.name
                                $customObject | Add-Member -notepropertyname "Cluster Name" -notepropertyvalue (Get-VCFCluster -id $cluster.id).name
                                $customObject | Add-Member -notepropertyname "ESXi Host FQDN" -notepropertyvalue (Get-VCFHost -id $assignedEsxiHost.id).fqdn
                                $customObject | Add-Member -notepropertyname "ESXi Host Version" -notepropertyvalue $assignedEsxiHost.esxiVersion
                                $customObject | Add-Member -notepropertyname "Hardware OEM" -notepropertyvalue $assignedEsxiHost.hardwareVendor
                                $customObject | Add-Member -notepropertyname "Hardware Platform" -notepropertyvalue $assignedEsxiHost.hardwareModel
                                $customObject | Add-Member -notepropertyname "CPU Sockets" -notepropertyvalue $assignedEsxiHost.cpu.cpuCores.Count
                                $customObject | Add-Member -notepropertyname "CPU Cores" -notepropertyvalue $assignedEsxiHost.cpu.Cores
                                $customObject | Add-Member -notepropertyname "Memory (GB)" -notepropertyvalue ([Math]::round(($assignedEsxiHost.memory.totalCapacityMB) / 1024))
                                $customObject | Add-Member -notepropertyname "Status" -notepropertyvalue $assignedEsxiHost.status
                            }
                            $allEsxiHostObject += $customObject

                        }
                    }
                }
                $allUnassignedEsxiHosts = (Get-VCFHost | Where-Object {$_.status -eq "UNASSIGNED_USEABLE"})
                foreach ($unassignedEsxiHost in $allUnassignedEsxiHosts) {
                    $customObject = New-Object -TypeName psobject
                    if ($PsBoundParameters.ContainsKey('anonymized')) {
                        $customObject | Add-Member -NotePropertyName 'Domain UUID' -NotePropertyValue ""
                        $customObject | Add-Member -notepropertyname "Cluster UUID" -notepropertyvalue ""
                        $customObject | Add-Member -notepropertyname "ESXi Host UUID" -notepropertyvalue $unassignedEsxiHost.id
                        $customObject | Add-Member -notepropertyname "ESXi Host Version" -notepropertyvalue $unassignedEsxiHost.esxiVersion
                        $customObject | Add-Member -notepropertyname "Hardware OEM" -notepropertyvalue $assignedEsxiHost.hardwareVendor
                        $customObject | Add-Member -notepropertyname "Hardware Platform" -notepropertyvalue $assignedEsxiHost.hardwareModel
                        $customObject | Add-Member -notepropertyname "CPU Sockets" -notepropertyvalue $assignedEsxiHost.cpu.cpuCores.Count
                        $customObject | Add-Member -notepropertyname "CPU Cores" -notepropertyvalue $assignedEsxiHost.cpu.Cores
                        $customObject | Add-Member -notepropertyname "Memory (GB)" -notepropertyvalue ([Math]::round(($unassignedEsxiHost.memory.totalCapacityMB) / 1024))
                        $customObject | Add-Member -notepropertyname "Status" -notepropertyvalue $unassignedEsxiHost.status
                    } else {
                        $customObject | Add-Member -notepropertyname "Domain Name" -notepropertyvalue ""
                        $customObject | Add-Member -notepropertyname "Cluster Name" -notepropertyvalue ""
                        $customObject | Add-Member -notepropertyname "ESXi Host FQDN" -notepropertyvalue (Get-VCFHost -id $unassignedEsxiHost.id).fqdn
                        $customObject | Add-Member -notepropertyname "ESXi Host Version" -notepropertyvalue $unassignedEsxiHost.esxiVersion
                        $customObject | Add-Member -notepropertyname "Hardware OEM" -notepropertyvalue $assignedEsxiHost.hardwareVendor
                        $customObject | Add-Member -notepropertyname "Hardware Platform" -notepropertyvalue $assignedEsxiHost.hardwareModel
                        $customObject | Add-Member -notepropertyname "CPU Sockets" -notepropertyvalue $assignedEsxiHost.cpu.cpuCores.Count
                        $customObject | Add-Member -notepropertyname "CPU Cores" -notepropertyvalue $assignedEsxiHost.cpu.Cores
                        $customObject | Add-Member -notepropertyname "Memory (GB)" -notepropertyvalue ([Math]::round(($unassignedEsxiHost.memory.totalCapacityMB) / 1024))
                        $customObject | Add-Member -notepropertyname "Status" -notepropertyvalue $unassignedEsxiHost.status
                    }
                    $allEsxiHostObject += $customObject
                }
                $allEsxiHostObject | Sort-Object -Property Status,  'Domain Name', 'Domain UUID', 'Cluster Name', 'Cluster UUID', 'ESXi Host FQDN', 'ESXi Host UUID'
            }
        }
    }
	Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Request-EsxiOverview

Function Request-ClusterOverview {
    <#
        .SYNOPSIS
        Returns overview of vSphere.

        .DESCRIPTION
        The Request-ClusterOverview cmdlet returns an overview of the vSphere environment managed by SDDC Manager.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity and authentication to the SDDC Manager instance
        - Validates that network connectivity and authentication to the vCenter Server instances
        - Collects the vSphere overview detail

        .EXAMPLE
        Request-ClusterOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
        This example will return an overview of the vSphere environment managed by the SDDC Manager instance.

        .EXAMPLE
        Request-ClusterOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -anonymized
        This example will return an overview of the vSphere environment managed by the SDDC Manager instance, but will anonymize the output.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$anonymized
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $allWorkloadDomains = Get-VCFWorkloadDomain
                $allClusterObject = New-Object System.Collections.ArrayList
                foreach ($domain in $allWorkloadDomains) {
                    foreach ($cluster in $domain.clusters) {
                        $customObject = New-Object -TypeName psobject
                        if ($PsBoundParameters.ContainsKey('anonymized')) {
                            $customObject | Add-Member -notepropertyname "Domain UUID" -notepropertyvalue $domain.id
                            $customObject | Add-Member -notepropertyname "Cluster UUID" -notepropertyvalue $cluster.id
                        } else {
                            $customObject | Add-Member -notepropertyname "Domain Name" -notepropertyvalue $domain.name  
                            $customObject | Add-Member -notepropertyname "Cluster Name" -notepropertyvalue (Get-VCFCluster -id $cluster.id).name
                        }
                        $customObject | Add-Member -notepropertyname "Total Hosts" -notepropertyvalue ((Get-VCFCluster -id $cluster.id).hosts | Measure-Object).Count
                        $customObject | Add-Member -notepropertyname "Principal Storage" -notepropertyvalue (Get-VCFCluster -id $cluster.id).primaryDatastoreType
                        $customObject | Add-Member -notepropertyname "Stretched Cluster" -notepropertyvalue (Get-VCFCluster -id $cluster.id).isStretched
                        $allClusterObject += $customObject
                    }
                }
                $allClusterObject | Sort-Object 'Domain Name','Cluster Name','Domain UUID','Cluster UUID'
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
        - Validates that network connectivity and authentication to the SDDC Manager instance
        - Collects the networking overview detail

        .EXAMPLE
        Request-NetworkOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
        This example will return an overview of the networking managed by the SDDC Manager instance.

        .EXAMPLE
        Request-NetworkOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -anonymized
        This example will return an overview of the networking managed by the SDDC Manager instance, but will anonymize the output.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$anonymized
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
                        if ($PsBoundParameters.ContainsKey('anonymized')) {
                            $customObject | Add-Member -notepropertyname "NSX Manager UUID" -notepropertyvalue $domain.nsxtCluster.id
                            $customObject | Add-Member -notepropertyname "NSX Manager Version" -notepropertyvalue (Get-VCFNsxtCluster -id $domain.nsxtCluster.id).version
                            $customObject | Add-Member -notepropertyname "NSX Stretched" -notepropertyvalue (Get-VCFNsxtCluster -id $domain.nsxtCluster.id).isShared
                            $customObject | Add-Member -notepropertyname "Domain UUID" -notepropertyvalue $domain.id
                        } else {
                            $customObject | Add-Member -notepropertyname "NSX Manager FQDN" -notepropertyvalue $domain.nsxtCluster.vipFqdn
                            $customObject | Add-Member -notepropertyname "NSX Manager Version" -notepropertyvalue (Get-VCFNsxtCluster -id $domain.nsxtCluster.id).version
                            $customObject | Add-Member -notepropertyname "NSX Stretched" -notepropertyvalue (Get-VCFNsxtCluster -id $domain.nsxtCluster.id).isShared
                            $customObject | Add-Member -notepropertyname "Domain Name" -notepropertyvalue $domain.name
                        }
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
        - Validates that network connectivity and authentication to the SDDC Manager instance
        - Collects the networking overview detail

        .EXAMPLE
        Request-VrealizeOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
        This example will return an overview of vRealize Suite managed by the SDDC Manager instance.

        .EXAMPLE
        Request-VrealizeOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -anonymized
        This example will return an overview of vRealize Suite managed by the SDDC Manager instance, but will anonymize the output.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$anonymized
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
                        if ($PsBoundParameters.ContainsKey('anonymized')) {
                            $customObject | Add-Member -notepropertyname "UUID" -notepropertyvalue (Invoke-Expression $apiCmdlet).id
                        } else {
                            if ($apiCmdlet -eq "Get-VCFvRSLCM") {
                                $customObject | Add-Member -notepropertyname "FQDN" -notepropertyvalue (Invoke-Expression $apiCmdlet).fqdn
                            } else {
                                $customObject | Add-Member -notepropertyname "FQDN" -notepropertyvalue (Invoke-Expression $apiCmdlet).loadBalancerFqdn
                            }
                        }
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

Function Request-ValidatedSolutionOverview {
    <#
        .SYNOPSIS
        Returns VMware Validated Solution Overview.

        .DESCRIPTION
        The Request-ValidatedSolutionOverview cmdlet returns an overview of VMware Validated Solutions deployed.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Collects the VMware Validated Solution details

        .EXAMPLE
        Request-ValidatedSolutionOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
        This example will return an overview of VMware Validated Solutions.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $allVvsObject = New-Object System.Collections.ArrayList

                # Validate IAM Deployment
                if (($vcfNsxDetails = Get-NsxtServerDetail -fqdn $server -username $user -password $pass -domainType MANAGEMENT)) {
                    if (Test-NSXTConnection -server $vcfNsxDetails.fqdn) {
                        if (Test-NSXTAuthentication -server $vcfNsxDetails.fqdn -user $vcfNsxDetails.adminUser -pass $vcfNsxDetails.adminPass) {
                            if ((Get-NsxtVidm).vidm_enable -eq "True") {
                                $iamEnabled = "Enabled"
                            } else {
                                $iamEnabled = "Not Enabled"
                            }
                        }
                    }
                }

                $customObject = New-Object -TypeName psobject
                $customObject | Add-Member -notepropertyname "Name" -notepropertyvalue "Identity and Access Management"
                $customObject | Add-Member -notepropertyname "Status" -notepropertyvalue $iamEnabled
                $allVvsObject += $customObject

                # Validate DRI Deployment
                $allWorkloadDomains = Get-VCFWorkloadDomain
                foreach ($domain in $allWorkloadDomains) {
                    if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain.name)) {
                        if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                            if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                                foreach ($cluster in Get-Cluster -Server $vcfVcenterDetails.fqdn ) {
                                    if (Get-WMCluster -Server $vcfVcenterDetails.fqdn) {
                                        $driEnabled = "Enabled"
                                    } else {
                                        $driEnabled = "Not Enabled"
                                    }
                                }
                            }
                            Disconnect-VIServer -Server $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                        }
                    }
                }

                $customObject = New-Object -TypeName psobject
                $customObject | Add-Member -notepropertyname "Name" -notepropertyvalue "Developer Ready Infrastructure"
                $customObject | Add-Member -notepropertyname "Status" -notepropertyvalue $driEnabled
                $allVvsObject += $customObject

                # Validate ILA Deployment
                if ((Get-VCFvRLI).status -eq "ACTIVE") {
                    if (($vcfVrliDetails = Get-vRLIServerDetail -fqdn $server -username $user -password $pass)) {
                        if (Test-vRLIConnection -server $vcfVrliDetails.fqdn) {
                            if (Test-vRLIAuthentication -server $vcfVrliDetails.fqdn -user $vcfVrliDetails.adminUser -pass $vcfVrliDetails.adminPass) {
                                if (Get-vRLISmtpConfiguration) {
                                    $ilaEnabled = "Enabled"
                                } else {
                                    $ilaEnabled = "Not Enabled"
                                }
                            }
                        }
                    }
                } else {
                    $ilaEnabled = "Not Enabled"
                }
                $customObject = New-Object -TypeName psobject
                $customObject | Add-Member -notepropertyname "Name" -notepropertyvalue "Intelligent Logging and Analytics"
                $customObject | Add-Member -notepropertyname "Status" -notepropertyvalue $ilaEnabled
                $allVvsObject += $customObject

                # Validate IOM Deployment
                if ((Get-VCFvROPS).status -eq "ACTIVE") {
                    if (($vcfVropsDetails = Get-vROPsServerDetail -fqdn $server -username $user -password $pass)) {
                        if (Test-vROPSConnection -server $vcfVropsDetails.loadBalancerFqdn) {
                            if (Test-vROPSAuthentication -server $vcfVropsDetails.loadBalancerFqdn -user $vcfVropsDetails.adminUser -pass $vcfVropsDetails.adminPass) {
                                if ((Get-vROPSCollectorGroup).Count -gt 1 ) {
                                    $iomEnabled = "Enabled"
                                } else {
                                    $iomEnabled = "Not Enabled"
                                }
                            }
                        }
                    }
                } else {
                    $iomEnabled = "Not Enabled"
                }
                $customObject = New-Object -TypeName psobject
                $customObject | Add-Member -notepropertyname "Name" -notepropertyvalue "Intelligent Operations Management"
                $customObject | Add-Member -notepropertyname "Status" -notepropertyvalue $iomEnabled
                $allVvsObject += $customObject

                # Validate PCA Deployment
                # TODO: Extract configadmin user and password from vRSLCM to check config in vRA
                if ((Get-VCFvRA).status -eq "ACTIVE") {
                    $vraEnabled = "Enabled"
                } else {
                    $vraEnabled = "Not Enabled"
                }
                $customObject = New-Object -TypeName psobject
                $customObject | Add-Member -notepropertyname "Name" -notepropertyvalue "Private Cloud Automation"
                $customObject | Add-Member -notepropertyname "Status" -notepropertyvalue $vraEnabled
                $allVvsObject += $customObject

                # Validate PDR Deployment
                if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT)) {
                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            if (((Get-View -Id 'ExtensionManager-ExtensionManager').ExtensionList | Where-Object {$_.Key -eq "com.vmware.vcDr"}) -and ((Get-View -Id 'ExtensionManager-ExtensionManager').ExtensionList | Where-Object {$_.Key -eq "com.vmware.vcHms"})) {
                                $pdrEnabled = "Enabled"
                            } else {
                                $pdrEnabled = "Not Enabled"
                            }
                        }
                        Disconnect-VIServer -Server $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                    }
                }

                $customObject = New-Object -TypeName psobject
                $customObject | Add-Member -notepropertyname "Name" -notepropertyvalue "Site Protection and Disaster Recovery"
                $customObject | Add-Member -notepropertyname "Status" -notepropertyvalue $pdrEnabled
                $allVvsObject += $customObject
                $allVvsObject | Sort-Object Name
            }
        }
    }
	Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Request-ValidatedSolutionOverview

##########################################  E N D   O F   F U N C T I O N S  ##########################################
#######################################################################################################################


#########################################################################################
#############################  Start Supporting Functions  ##############################

Function Test-VcfReportingPrereq {
    <#
		.SYNOPSIS
        Validate prerequisites to run the PowerShell module.

        .DESCRIPTION
        The Test-VcfReportingPrereq cmdlet checks that all the prerequisites have been met to run the PowerShell module.

        .EXAMPLE
        Test-VcfReportingPrereq
        This example runs the prerequisite validation.
    #>

    Try {
        $modules = @(
            @{ Name=("PowerVCF"); Version=("2.2.0")}
            @{ Name=("PowerValidatedSolutions"); Version=("1.10.0")}
            @{ Name=("VMware.PowerCLI"); Version=("12.7.0")}
            @{ Name=("VMware.vSphere.SsoAdmin"); Version=("1.3.8")}
        )
        foreach ($module in $modules ) {
            if ($PSEdition -eq "Desktop") {
                if ((Get-InstalledModule -Name $module.Name).Version -lt $module.Version) {
                    $message = "PowerShell Module: $($module.Name) Version: $($module.Version) Not Installed, Please update before proceeding."
                    Write-Warning $message; Write-Host ""
					Break
                } else {
                    $moduleCurrentVersion = (Get-InstalledModule -Name $module.Name).Version
                    $message = "PowerShell Module: $($module.Name) Version: $($moduleCurrentVersion) Found, Supports the minimum required version."
                    $message
                }
            } else {
                if (!$module -eq "VMware.PowerCLI") {
                    if ((Get-Module -Name $module.Name).Version -lt $module.Version) {
                        $message = "PowerShell Module: $($module.Name) Version: $($module.Version) Not Installed, Please update before proceeding."
                        Write-Warning $message; Write-Host ""
					Break
                    } else {
                        $moduleCurrentVersion = (Get-InstalledModule -Name $module.Name).Version
                        $message = "PowerShell Module: $($module.Name) Version: $($moduleCurrentVersion) Found, Supports the minimum required version."
                        $message
                    }
                }
            }

        }
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}
Export-ModuleMember -Function Test-VcfReportingPrereq
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
    if ($PSEdition -eq "Core" -and ($PSVersionTable.OS).Split(' ')[0] -eq "Linux") {
        $reportFolder = ($reportFolder).split('\') -join '/' | Split-Path -NoQualifier
    }
    if (!(Test-Path -Path $reportFolder)) {
        New-Item -Path $reportFolder -ItemType "directory" | Out-Null
    }
    $reportName = $reportFolder + $filetimeStamp + "-" + $reportType + ".htm"
    $reportName
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
        Invoke-SddcCommand -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -vmUser root -vmPass VMw@re1! -command "chage -l backup"
        This example runs the command provided on the SDDC Manager appliance as the root user.

        .EXAMPLE
        Invoke-SddcCommand -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -vmUser vcf -vmPass VMw@re1! -command "echo Hello World."
        This example runs the command provided on the SDDC Manager appliance as the vcf user.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$vmUser,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$vmPass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$command
    )

    if (Test-VCFConnection -server $server) {
        if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT)) {
                if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                    if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                        $output = Invoke-VMScript -VM ($server.Split(".")[0]) -ScriptText $command -GuestUser $vmUser -GuestPassword $vmPass -Server $vcfVcenterDetails.fqdn
                        $output
                    }
                    Disconnect-VIServer -Server $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                }
            }
        }
    }
}
Export-ModuleMember -Function Invoke-SddcCommand

Function Copy-FiletoSddc {
    <#
		.SYNOPSIS
        Copy a file to SDDC Manager.

        .DESCRIPTION
        The Copy-FiletoSddc cmdlet copies files to the SDDC Manager appliance. The cmdlet connects to SDDC
        Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the Management Domain vCenter Server instance
        - Copies the files to the SDDC Manager appliance

        .EXAMPLE
        Copy-FiletoSddc -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -rootPass VMw@re1! -source "C:\Temp\foo.txt" -destination "/home/vcf/foo.txt"
        This example copies a file to the SDDC Manager appliance.

        .EXAMPLE
        Copy-FiletoSddc -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -rootPass VMw@re1! -source "C:\Temp\bar" -destination "/home/vcf/"
        This example copies a file to the SDDC Manager appliance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$vmUser,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$vmPass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$source,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$destination
    )

    if (Test-VCFConnection -server $server) {
        if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT)) {
                if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                    if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                        $output = Copy-VMGuestFile -VM ($server.Split('.')[0]) -LocalToGuest -GuestUser $vmUser -GuestPassword $vmPass -Source $source -Destination $destination -Server $vcfVcenterDetails.fqdn
                        $output
                    }
                    Disconnect-VIServer -Server $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                }
            }
        }
    }
}
Export-ModuleMember -Function Copy-FiletoSddc

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
        } else {
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

    # Define the default Clarity Cascading Style Sheets (CSS) for the HTML report Header
    if ($PsBoundParameters.ContainsKey("dark")) {
        $clarityCssHeader = '
        <head>
        <style>
            <!--- Used Clarify CSS components for this project --->
            article, aside, details, figcaption, figure, footer, header, main, menu, nav, section, summary { display: block; }
            .main-container { display: flex; flex-direction: column; height: 100vh; background: var(--clr-global-app-background, #21333b); }
            header.header-6, .header.header-6 { background-color: #0e161b; }
            header, .header { display: flex; color: #fafafa; background-color: #0e161b; height: 3rem; white-space: nowrap; }
            .nav { display: flex; height: 1.8rem; list-style-type: none; align-items: center; margin: 0; width: 100%; white-space: nowrap; box-shadow: 0 -0.05rem 0 #495865 inset; }
            .nav .nav-item { display: inline-block; margin-right: 1.2rem; }
            .nav .nav-item.active > .nav-link { color: white; box-shadow: 0 -0.05rem 0 #495865 inset; }
            .nav .nav-link { color: #acbac3; font-size: 0.7rem; font-weight: 400; letter-spacing: normal; line-height: 1.8rem; display: inline-block; padding: 0 0.15rem; box-shadow: none; }
            .nav .nav-link.btn { text-transform: none; margin: 0; margin-bottom: -0.05rem; border-radius: 0; }
            .nav .nav-link:hover, .nav .nav-link:focus, .nav .nav-link:active { color: inherit; }
            .nav .nav-link:hover, .nav .nav-link.active { box-shadow: 0 -0.15rem 0 #4aaed9 inset; transition: box-shadow 0.2s ease-in; }
            .nav .nav-link:hover, .nav .nav-link:focus, .nav .nav-link:active, .nav .nav-link.active { text-decoration: none; }
            .nav .nav-link.active { color: white; font-weight: 400; }
            .nav .nav-link.nav-item { margin-right: 1.2rem; }
            .sub-nav, .subnav { display: flex; box-shadow: 0 -0.05rem 0 #cccccc inset; justify-content: space-between; align-items: center; background-color: #17242b; height: 1.8rem; }
            .sub-nav .nav, .subnav .nav { flex: 1 1 auto; padding-left: 1.2rem; }
            .sub-nav aside, .subnav aside { flex: 0 0 auto; display: flex; align-items: center; height: 1.8rem; padding: 0 1.2rem; }
            .sub-nav aside > :last-child, .subnav aside > :last-child { margin-right: 0; padding-right: 0; }
            .sidenav { line-height: 1.2rem; max-width: 15.6rem; min-width: 10.8rem; width: 18%; border-right: 0.05rem solid #152228; display: flex; flex-direction: column; }
            .sidenav .sidenav-content { flex: 1 1 auto; overflow-x: hidden; padding-bottom: 1.2rem; }
            .sidenav .sidenav-content .nav-link { border-radius: 0; border-top-left-radius: 0.15rem; border-bottom-left-radius: 0.15rem; display: inline-block; color: inherit; cursor: pointer; text-decoration: none; width: 100%; }
            .sidenav .sidenav-content > .nav-link { margin: 1.2rem 0 0 1.5rem; padding-left: 0.6rem; color: #acbac3; font-weight: 500; font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-size: 0.7rem; line-height: 1.2rem; letter-spacing: normal; }
            .sidenav .sidenav-content > .nav-link:hover { background: #324f62; }
            .sidenav .sidenav-content > .nav-link.active { background: #324f62; color: black; }
            .sidenav .nav-group { color: #acbac3; font-weight: 400; font-size: 0.7rem; letter-spacing: normal; margin-top: 1.2rem; width: 100%; }
            .sidenav .nav-group .nav-list, .sidenav .nav-group label { padding: 0 0 0 1.8rem; cursor: pointer; display: inline-block; width: 100%; margin: 0 0.3rem; }
            .sidenav .nav-group .nav-list { list-style: none; margin-top: 0; }
            .sidenav .nav-group .nav-list .nav-link { line-height: 0.8rem; padding: 0.2rem 0 0.2rem 0.6rem; }
            .sidenav .nav-group .nav-list .nav-link:hover { background: #324f62; }
            .sidenav .nav-group .nav-list .nav-link.active { background: #324f62; color: black; }
            .sidenav .nav-group label { color: #acbac3; font-weight: 500; font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-size: 0.7rem; line-height: 1.2rem; letter-spacing: normal; }
            .sidenav .nav-group input[type=checkbox] { position: absolute; clip: rect(1px, 1px, 1px, 1px); clip-path: inset(50%); padding: 0; border: 0; height: 1px; width: 1px; overflow: hidden; white-space: nowrap; top: 0; left: 0; }
            .sidenav .nav-group input[type=checkbox]:focus + label { outline: #3b99fc auto 0.25rem; }
            .sidenav .collapsible label { padding: 0 0 0 1.3rem; }
            .sidenav .collapsible label:after { content: ""; float: left; height: 0.5rem; width: 0.5rem; transform: translateX(-0.4rem) translateY(0.35rem); background-image: url("data:image/svg+xml;charset=utf8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%2012%2012%22%3E%0A%20%20%20%20%3Cdefs%3E%0A%20%20%20%20%20%20%20%20%3Cstyle%3E.cls-1%7Bfill%3A%239a9a9a%3B%7D%3C%2Fstyle%3E%0A%20%20%20%20%3C%2Fdefs%3E%0A%20%20%20%20%3Ctitle%3ECaret%3C%2Ftitle%3E%0A%20%20%20%20%3Cpath%20class%3D%22cls-1%22%20d%3D%22M6%2C9L1.2%2C4.2a0.68%2C0.68%2C0%2C0%2C1%2C1-1L6%2C7.08%2C9.84%2C3.24a0.68%2C0.68%2C0%2C1%2C1%2C1%2C1Z%22%2F%3E%0A%3C%2Fsvg%3E%0A"); background-repeat: no-repeat; background-size: contain; vertical-align: middle; margin: 0; }
            .sidenav .collapsible input[type=checkbox]:checked ~ .nav-list, .sidenav .collapsible input[type=checkbox]:checked ~ ul { height: 0; display: none; }
            .sidenav .collapsible input[type=checkbox] ~ .nav-list, .sidenav .collapsible input[type=checkbox] ~ ul { height: auto; }
            .sidenav .collapsible input[type=checkbox]:checked ~ label:after { transform: rotate(-90deg) translateX(-0.35rem) translateY(-0.4rem); }
            body:not([cds-text]) { color: #acbac3; font-weight: 400; font-size: 0.7rem; letter-spacing: normal; line-height: 1.2rem; margin-bottom: 0px; font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; margin-top: 0px !important; }
            html:not([cds-text]) { color: #eaedf0; font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-size: 125%; }
            a:link { color: #4aaed9; text-decoration: none; }
            h1:not([cds-text]) { color: #eaedf0; font-weight: 200; font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-size: 1.6rem; letter-spacing: normal; line-height: 2.4rem; margin-top: 1.2rem; margin-bottom: 0; }
            h2:not([cds-text]) { color: #eaedf0; font-weight: 200; font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-size: 1.4rem; letter-spacing: normal; line-height: 2.4rem; margin-top: 1.2rem; margin-bottom: 0; }
            h3:not([cds-text]) { color: #eaedf0; font-weight: 200; font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-size: 1.1rem; letter-spacing: normal; line-height: 1.2rem; margin-top: 1.2rem; margin-bottom: 0; }
            h4:not([cds-text]) { color: #eaedf0; font-weight: 200; font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-size: 0.9rem; letter-spacing: normal; line-height: 1.2rem; margin-top: 1.2rem; margin-bottom: 0; }
            .table th { color: #eaedf0; font-size: 0.55rem; font-weight: 600; letter-spacing: 0.03em; background-color: #1b2a32; vertical-align: bottom; border-bottom-style: solid; border-bottom-width: 0.05rem; border-bottom-color: #495865; border-top: 0 none; }
            .table { border-collapse: separate; border-style: solid; border-width: 0.05rem; border-color: #495865; border-radius: 0.15rem; background-color: #21333b; color: #acbac3; margin: 0; margin-top: 1.2rem; max-width: 100%; width: 100%; }

            h3 { display: block; font-size: 1.17em; margin-block-start: 1em; margin-block-end: 1em; margin-inline-start: 0px; margin-inline-end: 0px; font-weight: bold; }
            h4 { display: block; margin-block-start: 1.33em; margin-block-end: 1.33em; margin-inline-start: 0px; margin-inline-end: 0px; font-weight: bold; }
            .table th, .table td {font-size: 0.65rem; line-height: 0.7rem; border-top-style: solid; border-top-width: 0.05rem; border-top-color: #495865; padding: 0.55rem 0.6rem 0.55rem; text-align: left; vertical-align: top; }
            th { display: table-cell; vertical-align: inherit; font-weight: bold; text-align: -internal-center; }
            table { display: table; border-collapse: separate; box-sizing: border-box; text-indent: initial; border-spacing: 2px; border-color: gray; }
        '
    } else {
        $clarityCssHeader = '
        <head>
		<style>
			<!--- Used Clarify CSS components for this project --->
            article, aside, details, figcaption, figure, footer, header, main, menu, nav, section, summary { display: block; }
            .main-container { display: flex; flex-direction: column; height: 100vh; background: var(--clr-global-app-background, #fafafa); }
            header.header-6, .header.header-6 { background-color: var(--clr-header-6-bg-color, #00364d); }
            header, .header { display: flex; color: var(--clr-header-font-color, #fafafa); background-color: var(--clr-header-bg-color, #333333); height: 3rem; white-space: nowrap; }
            .nav {display: flex; height: 1.8rem; list-style-type: none; align-items: center; margin: 0; width: 100%; white-space: nowrap; box-shadow: 0 -0.05rem 0 #cccccc inset; box-shadow: 0 -0.05rem 0 var(--clr-nav-box-shadow-color, #cccccc) inset; }
            .nav .nav-item { display: inline-block; margin-right: 1.2rem; }
            .nav .nav-item.active > .nav-link { color: black; color: var(--clr-nav-link-active-color, black); box-shadow: 0 -0.05rem 0 #cccccc inset; box-shadow: 0 -0.05rem 0 var(--clr-nav-box-shadow-color, #cccccc) inset; }
            .nav .nav-link { color: #666666; color: var(--clr-nav-link-color, #666666); font-size: 0.7rem; font-weight: 400; font-weight: var(--clr-nav-link-font-weight, 400); letter-spacing: normal; line-height: 1.8rem; display: inline-block; padding: 0 0.15rem; box-shadow: none; }
            .nav .nav-link.btn { text-transform: none; margin: 0; margin-bottom: -0.05rem; border-radius: 0; }
            .nav .nav-link:hover, .nav .nav-link:focus, .nav .nav-link:active { color: inherit; }
            .nav .nav-link:hover, .nav .nav-link.active { box-shadow: 0 -0.15rem 0 #0072a3 inset; box-shadow: 0 -0.15rem 0 var(--clr-nav-active-box-shadow-color, #0072a3) inset; transition: box-shadow 0.2s ease-in; }
            .nav .nav-link:hover, .nav .nav-link:focus, .nav .nav-link:active, .nav .nav-link.active { text-decoration: none; }
            .nav .nav-link.active { color: black; color: var(--clr-nav-link-active-color, black); font-weight: 400; font-weight: var(--clr-nav-link-active-font-weight, 400); }
            .nav .nav-link.nav-item { margin-right: 1.2rem; }
            .sub-nav, .subnav { display: flex; box-shadow: 0 -0.05rem 0 #cccccc inset; box-shadow: 0 -0.05rem 0 var(--clr-nav-box-shadow-color, #cccccc) inset; justify-content: space-between; align-items: center; background-color: white; background-color: var(--clr-subnav-bg-color, white); height: 1.8rem; }
            .sub-nav .nav, .subnav .nav { flex: 1 1 auto; padding-left: 1.2rem; }
            .sub-nav aside, .subnav aside { flex: 0 0 auto; display: flex; align-items: center; height: 1.8rem; padding: 0 1.2rem; }
            .sub-nav aside > :last-child, .subnav aside > :last-child { margin-right: 0; padding-right: 0; }
            .sidenav { line-height: 1.2rem; max-width: 15.6rem; min-width: 10.8rem; width: 18%; border-right: 0.05rem solid #cccccc; display: flex; flex-direction: column; }
            .sidenav .collapsible label padding: 0 0 0 1.3rem; }
            .sidenav .nav-group label {color: #333333; color: var(--clr-sidenav-header-color, #333333); font-weight: 500; font-weight: var(--clr-sidenav-header-font-weight, 500); font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-family: var(--clr-sidenav-header-font-family, ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif); font-size: 0.7rem; line-height: 1.2rem; letter-spacing: normal; }
            .sidenav { line-height: 1.2rem; max-width: 15.6rem; min-width: 10.8rem; width: 18%; border-right: 0.05rem solid #cccccc; display: flex; flex-direction: column; }
            .sidenav .sidenav-content { flex: 1 1 auto; overflow-x: hidden; padding-bottom: 1.2rem; }
            .sidenav .sidenav-content .nav-link { border-radius: 0; border-top-left-radius: 0.15rem; border-top-left-radius: var(--clr-sidenav-link-active-border-radius, 0.15rem); border-bottom-left-radius: 0.15rem; border-bottom-left-radius: var(--clr-sidenav-link-active-border-radius, 0.15rem); display: inline-block; color: inherit; cursor: pointer; text-decoration: none; width: 100%; }
            .sidenav .sidenav-content > .nav-link { margin: 1.2rem 0 0 1.5rem; padding-left: 0.6rem; color: #333333; color: var(--clr-sidenav-header-color, #333333); font-weight: 500; font-weight: var(--clr-sidenav-header-font-weight, 500); font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-family: var(--clr-sidenav-header-font-family, ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif);font-size: 0.7rem; line-height: 1.2rem; letter-spacing: normal; }
            .sidenav .sidenav-content > .nav-link:hover { background: #e8e8e8; background: var(--clr-sidenav-link-hover-color, #e8e8e8); }
            .sidenav .sidenav-content > .nav-link.active { background: #d8e3e9; background: var(--clr-sidenav-link-active-bg-color, #d8e3e9); color: black; color: var(--clr-sidenav-link-active-color, black); }
            .sidenav .nav-group { color: #666666; color: var(--clr-sidenav-color, #666666); font-weight: 400; font-weight: var(--clr-sidenav-font-weight, 400); font-size: 0.7rem; letter-spacing: normal; margin-top: 1.2rem; width: 100%; }
            .sidenav .nav-group .nav-list, .sidenav .nav-group label { padding: 0 0 0 1.8rem; cursor: pointer; display: inline-block; width: 100%; margin: 0 0.3rem; }
            .sidenav .nav-group .nav-list { list-style: none; margin-top: 0; }
            .sidenav .nav-group .nav-list .nav-link { line-height: 0.8rem; padding: 0.2rem 0 0.2rem 0.6rem; }
            .sidenav .nav-group .nav-list .nav-link:hover { background: #e8e8e8; background: var(--clr-sidenav-link-hover-color, #e8e8e8); }
            .sidenav .nav-group .nav-list .nav-link.active { background: #d8e3e9; background: var(--clr-sidenav-link-active-bg-color, #d8e3e9); color: black; color: var(--clr-sidenav-link-active-color, black); }
            .sidenav .nav-group label { color: #333333; color: var(--clr-sidenav-header-color, #333333); font-weight: 500; font-weight: var(--clr-sidenav-header-font-weight, 500); font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-family: var(--clr-sidenav-header-font-family, ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif); font-size: 0.7rem; line-height: 1.2rem; letter-spacing: normal; }
            .sidenav .nav-group input[type=checkbox] { position: absolute; clip: rect(1px, 1px, 1px, 1px); clip-path: inset(50%); padding: 0; border: 0; height: 1px; width: 1px; overflow: hidden; white-space: nowrap; top: 0; left: 0; }
            .sidenav .nav-group input[type=checkbox]:focus + label { outline: #3b99fc auto 0.25rem; }
            .sidenav .collapsible label { padding: 0 0 0 1.3rem; }
            .sidenav .collapsible label:after { content: ""; float: left; height: 0.5rem; width: 0.5rem; transform: translateX(-0.4rem) translateY(0.35rem); background-image: url("data:image/svg+xml;charset=utf8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%2012%2012%22%3E%0A%20%20%20%20%3Cdefs%3E%0A%20%20%20%20%20%20%20%20%3Cstyle%3E.cls-1%7Bfill%3A%239a9a9a%3B%7D%3C%2Fstyle%3E%0A%20%20%20%20%3C%2Fdefs%3E%0A%20%20%20%20%3Ctitle%3ECaret%3C%2Ftitle%3E%0A%20%20%20%20%3Cpath%20class%3D%22cls-1%22%20d%3D%22M6%2C9L1.2%2C4.2a0.68%2C0.68%2C0%2C0%2C1%2C1-1L6%2C7.08%2C9.84%2C3.24a0.68%2C0.68%2C0%2C1%2C1%2C1%2C1Z%22%2F%3E%0A%3C%2Fsvg%3E%0A"); background-repeat: no-repeat; background-size: contain; vertical-align: middle; margin: 0; }
            .sidenav .collapsible input[type=checkbox]:checked ~ .nav-list, .sidenav .collapsible input[type=checkbox]:checked ~ ul { height: 0; display: none; }
            .sidenav .collapsible input[type=checkbox] ~ .nav-list, .sidenav .collapsible input[type=checkbox] ~ ul { height: auto; }
            .sidenav .collapsible input[type=checkbox]:checked ~ label:after { transform: rotate(-90deg) translateX(-0.35rem) translateY(-0.4rem); }
            body:not([cds-text]) { color: var(--clr-p1-color, #666666); font-weight: var(--clr-p1-font-weight, 400); font-size: 0.7rem; letter-spacing: normal; line-height: 1.2rem; margin-bottom: 0px; font-family: var(--clr-font, ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif); margin-top: 0px !important; }
            html:not([cds-text]) { color: var(--clr-global-font-color, #666666); font-family: var(--clr-font, ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif); font-size: 125%; }
            a:link { color: var(--clr-link-color, #0072a3); text-decoration: none; }
            h1:not([cds-text]) { color: var(--clr-h1-color, black); font-weight: var(--clr-h1-font-weight, 200); font-family: var(--clr-h1-font-family, ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif); font-size: 1.6rem; letter-spacing: normal; line-height: 2.4rem; margin-top: 1.2rem; margin-bottom: 0px; }
			h2:not([cds-text]) { color: var(--clr-h2-color, black); font-weight: var(--clr-h2-font-weight, 200); font-family: var(--clr-h2-font-family, ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif); font-size: 1.4rem; letter-spacing: normal; line-height: 2.4rem; margin-top: 1.2rem; margin-bottom: 0px; }
			h3:not([cds-text]) { color: var(--clr-h3-color, black); font-weight: var(--clr-h3-font-weight, 200); font-family: var(--clr-h3-font-family, ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif); font-size: 1.1rem; letter-spacing: normal; line-height: 1.2rem; margin-top: 1.2rem; margin-bottom: 0px; }
			h4:not([cds-text]) { color: var(--clr-h4-color, black); font-weight: var(--clr-h4-font-weight, 200); font-family: var(--clr-h4-font-family, ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif); font-size: 0.9rem; letter-spacing: normal; line-height: 1.2rem; margin-top: 1.2rem; margin-bottom: 0px; }
            .table th { color: var(--clr-thead-color, #666666); font-size: 0.55rem; font-weight: 600; letter-spacing: 0.03em; background-color: var(--clr-thead-bgcolor, #fafafa); vertical-align: bottom; border-bottom-style: solid; border-bottom-width: var(--clr-table-borderwidth, 0.05rem); border-bottom-color: var(--clr-table-border-color, #cccccc); border-top: 0px none; }
            .table { border-collapse: separate; border-style: solid; border-width: var(--clr-table-borderwidth, 0.05rem); border-color: var(--clr-table-border-color, #cccccc); border-radius: var(--clr-table-border-radius, 0.15rem); background-color: var(--clr-table-bgcolor, white); color: var(--clr-table-font-color, #666666); margin: 1.2rem 0px 0px; max-width: 100%; width: 100%; }

			a { background-color: transparent; }
			abbr[title] { border-bottom: none; text-decoration: underline dotted; }
			b, strong { font-weight: inherit; }
			b, strong { font-weight: bolder; }
			[type="checkbox"], [type="radio"] { box-sizing: border-box; padding: 0px; }
			pre { border-color: var(--clr-color-neutral-400, #cccccc); border-width: var(--clr-global-borderwidth, 0.05rem); border-style: solid; border-radius: var(--clr-global-borderradius, 0.15rem); }
			ul:not([cds-list]), ol:not([cds-list]) { list-style-position: inside; margin-left: 0px; margin-top: 0px; margin-bottom: 0px; padding-left: 0px; }
			li > ul:not([cds-list]) { margin-top: 0px; margin-left: 1.1em; }
			body p:not([cds-text]) { color: var(--clr-p1-color, #666666); font-weight: var(--clr-p1-font-weight, 400); font-size: 0.7rem; letter-spacing: normal; line-height: 1.2rem; margin-top: 1.2rem; margin-bottom: 0px; }
			a:visited { color: var(--clr-link-visited-color, #5659b8); text-decoration: none; }
			.main-container .content-container .content-area > :first-child { margin-top: 0px; }
			.nav .nav-link:hover, .nav .nav-link.active { box-shadow: 0 -0.15rem 0 var(--clr-nav-active-box-shadow-color, #0072a3) inset; transition: box-shadow 0.2s ease-in 0s; }
			.nav .nav-link.active { color: var(--clr-nav-link-active-color, black); font-weight: var(--clr-nav-link-active-font-weight, 400); }
			:root { --clr-subnav-bg-color:var(--clr-color-neutral-0); --clr-nav-box-shadow-color:var(--clr-color-neutral-400); }
			:root { --clr-sidenav-border-color:var(--clr-color-neutral-400); --clr-sidenav-border-width:var(--clr-global-borderwidth); --clr-sidenav-link-hover-color:var(--clr-color-neutral-200); --clr-sidenav-link-active-color:var(--clr-color-neutral-1000); --clr-sidenav-link-active-bg-color:var(--clr-global-selection-color); --clr-sidenav-link-active-border-radius:var(--clr-global-borderradius); --clr-sidenav-header-color:var(--clr-h6-color); --clr-sidenav-header-font-weight:var(--clr-h6-font-weight); --clr-sidenav-header-font-family:var(--clr-h6-font-family); --clr-sidenav-color:var(--clr-p1-color); --clr-sidenav-font-weight:var(--clr-p1-font-weight); }
			.table th, .table td { font-size: 0.65rem; line-height: 0.7rem; border-top-style: solid; border-top-width: var(--clr-table-borderwidth, 0.05rem); border-top-color: var(--clr-tablerow-bordercolor, #e8e8e8); padding: 0.55rem 0.6rem; text-align: left; vertical-align: top; }
        '
    }
    $clarityCssShared = '
            .alertOK { color: #61B715; font-weight: bold }
            .alertWarning { color: #FDD008; font-weight: bold }
            .alertCritical { color: #F55047; font-weight: bold }
            .table th, .table td { text-align: left; }

            :root { --cds-global-base: 20; }
            body { margin: 0px; }
            .main-container .content-container .sidenav { flex: 0 0 auto; order: -1; overflow: hidden; }
            .main-container .content-container .content-area > :first-child { margin-top: 0; }
            .main-container .content-container .content-area { flex: 1 1 auto; overflow-y: auto; -webkit-overflow-scrolling: touch; padding: 1.2rem 1.2rem 1.2rem 1.2rem; }
            .main-container header, .main-container .header { flex: 0 0 3rem; }
            .main-container .header .branding { max-width: auto; min-width: 0px; overflow: hidden; }
            .main-container .sub-nav, .main-container .subnav { flex: 0 0 1.8rem; }
            .main-container .content-container { display: flex; flex: 1 1 auto; min-height: 0.05rem; }
            header .branding, .header .branding { display: flex; flex: 0 0 auto; min-width: 10.2rem; padding: 0px 1.2rem; height: 3rem; }
            header .branding .title, .header .branding .title { color: #fafafa; font-weight: 400; font-family: ClarityCityRegular, "Avenir Next", "Helvetica Neue", Arial, sans-serif; font-size: 0.8rem; letter-spacing: 0.01em; line-height: 3rem; text-decoration: none; }
            header .branding > a, header .branding > .nav-link, .header .branding > a, .header .branding > .nav-link { display: inline-flex; align-items: center; height: 3rem; }
            header .branding .clr-icon, header .branding cds-icon, header .branding clr-icon, .header .branding .clr-icon, .header .branding cds-icon, .header .branding clr-icon { flex-grow: 0; flex-shrink: 0; height: 1.8rem; width: 1.8rem; margin-right: 0.45rem; }

            ul:not([cds-list]), ol:not([cds-list]) { list-style-position: inside; margin-left: 0; margin-top: 0; margin-bottom: 0; padding-left: 0; }
            a { background-color: transparent; -webkit-text-decoration-skip: objects; }
            h1 { font-size: 2em; margin: 0.67em 0px; }
            img { border-style: none; }
            img { vertical-align: middle; }
            *, ::before, ::after { box-sizing: border-box; }
            *, ::before, ::after { box-sizing: inherit; }
            table { border-spacing: 0px; }
            pre { margin: 0.6rem 0px; }
            html { box-sizing: border-box; }
			html { -webkit-tap-highlight-color: transparent; }
            html { -ms-overflow-style: scrollbar; -webkit-tap-highlight-color: rgba(0, 0, 0, 0); }
            html { font-family: sans-serif; line-height: 1.15; -ms-text-size-adjust: 100%; -webkit-text-size-adjust: 100%; }
            .table tbody tr:first-child td { border-top: 0px none; }
			.table thead th:first-child { border-top-right-radius: 0px; border-bottom-right-radius: 0px; border-bottom-left-radius: 0px; border-top-left-radius: var(--clr-table-cornercellradius, 0.1rem); }
			.table thead th:last-child { border-top-left-radius: 0px; border-bottom-right-radius: 0px; border-bottom-left-radius: 0px; border-top-right-radius: var(--clr-table-cornercellradius, 0.1rem); }
			.table tbody:last-child tr:last-child td:first-child { border-top-left-radius: 0px; border-top-right-radius: 0px; border-bottom-right-radius: 0px; border-bottom-left-radius: var(--clr-table-cornercellradius, 0.1rem); }
			.table tbody:last-child tr:last-child td:last-child { border-top-left-radius: 0px; border-top-right-radius: 0px; border-bottom-left-radius: 0px; border-bottom-right-radius: var(--clr-table-cornercellradius, 0.1rem); }

            @font-face {font-family: ClarityCityRegular;src: url(data:font/ttf;base64,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AvQAWwLlABkEKwAeBCsAHgQrAB4EKwAeBCsAHgKlABwCoQATAqEAEwKhABMCoQATAqEAEwJlACwCZQAsAmUALAJlACwCLQAkAi0AJAItACQCLQAkAi0AJAItACQCLQAkAi0AJAItACQCLQAkA7IAJAJ7AFcCBwApAgcAKQIHACkCBwApAnsALwJZACsCpQAvAnsALwJHACwCRwAsAkcALAJHACwCRwAsAkcALAJYACwCRwAsAkcALAJYACwCRwAsAT0AGAJ2ACoCdgAqAnYAKgJZAFcA+QBLAPkAVwD5AFcA+f/2APn/7wD5/9IA+f/iAPkAMADv/84A7//OAiUAVwIlAFcA+QBXAPkAVwEWAFcBJwAcA4kAVwJZAFcCWQBXAlkAVwJZAFcCWQBXAmkAKgJpACoCaQAqAmkAKgJpACoCaQAqAmkAKgKBADMCaQAqBCAAKgJ7AFcCfABYAnsALwGMAFcBjABXAYwAVgGMAFcB3gAhAd4AIQHeACEB3gAhAkMAVwFZABUBuQAVAVkAFQJZAEsCWQBLAlkASwJZAEsCWQBLAlkASwJZAEsCWQBLAlkASwIRAAoDHQAQAx0AEAMdABADHQAQAx0AEAH/AAwCGAAJAhgACQIYAAkCGAAJAhgACQHbACEB2wAhAdsAIQHbACECewAvAnsALwJ7AC8CewAvAnsALwJ7AC8CewAvAnsALwJ7AC8CewAvArMAPAFlABQCNQAiAkYAHgJMABsCUQA3AmgAPwIDABYCbQA7AmgAMgFEAGwBOgBlATMAYwE1AGMC1ABsAT0AaAE9AGkCCQAiAgkAMwFBAG0BrgBfAc8AVgKxAC8BtAAAAbQAAAFIADUBSAAaAWIAFgFiABsBcgBpAXIAHQGvAFYCfQBWA64AVgMAAFYB4ABUAeAAUAHgAFQBGABQARgAVAIBACICAAAsATsAIgE6ACwBygBdARYAXQPoAAAB9AAAAPoAAAETAAAApgAAAU0AAAJcAFECkgBGAzkAUAKcAFUC8QA6Ak8AQgLPAIICFgBOAlMARALRAIMCUQBPAlEAOwIbAG0B/AA/A0YAPwS6AD8DqABJAsIAPwKYAD0DrQBKApUAVANBAFMBQgCDAAD/UgAA/10BBwAeAZEANQFbACYBJQAwAVsAJgGxAEsA8QBLAQMAHQHOAB0B4gBWASYAQwFNAD8BxABC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)
        </style>
        </head>
            <body>
                <div class="main-container">
                    <header class="header header-6">
                        <div class="branding">
                            <a href="">
                                <cds-icon shape="vm-bug">
                                    <img height="36px" width="36px" src="data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4KPCEtLSBHZW5lcmF0b3I6IEFkb2JlIElsbHVzdHJhdG9yIDI2LjIuMSwgU1ZHIEV4cG9ydCBQbHVnLUluIC4gU1ZHIFZlcnNpb246IDYuMDAgQnVpbGQgMCkgIC0tPgo8c3ZnIHZlcnNpb249IjEuMSIgaWQ9IkxheWVyXzEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiIHg9IjBweCIgeT0iMHB4IgoJIHZpZXdCb3g9IjAgMCAzNiAzNiIgc3R5bGU9ImVuYWJsZS1iYWNrZ3JvdW5kOm5ldyAwIDAgMzYgMzY7IiB4bWw6c3BhY2U9InByZXNlcnZlIj4KPHN0eWxlIHR5cGU9InRleHQvY3NzIj4KCS5zdDB7ZmlsbDojMDA5MURBO30KCS5zdDF7ZmlsbDojMUQ0MjhBO30KCS5zdDJ7ZmlsbDojMDBDMUQ1O30KPC9zdHlsZT4KPHBhdGggY2xhc3M9InN0MCIgZD0iTTI4LjIsMzAuNGMtMC4zLDAtMC41LTAuMi0wLjYtMC40Yy0wLjItMC40LDAtMC44LDAuMy0wLjljMy45LTEuOCw2LjQtNS43LDYuNC05LjljMC0yLjMtMC43LTQuNC0yLTYuMwoJYy0xLjMtMS44LTMtMy4yLTUuMS00Yy0wLjQtMC4xLTAuNi0wLjYtMC40LTAuOWMwLjEtMC40LDAuNi0wLjYsMC45LTAuNGMyLjMsMC45LDQuMywyLjQsNS44LDQuNWMxLjUsMi4xLDIuMyw0LjUsMi4zLDcuMQoJYzAsNC44LTIuOCw5LjItNy4yLDExLjJDMjguNCwzMC40LDI4LjMsMzAuNCwyOC4yLDMwLjR6Ii8+CjxwYXRoIGNsYXNzPSJzdDEiIGQ9Ik0yMy4yLDExLjNjLTAuMSwwLTAuMiwwLTAuMywwYy0wLjUtMS44LTEuNi0zLjMtMy4xLTQuNWMtMS43LTEuMy0zLjctMi01LjgtMmMtNS4xLDAtOS4zLDQuMS05LjMsOS4yCgljMCwwLDAsMC4xLDAsMC4xYy0zLjUsMS4xLTUuNCw0LjktNC4zLDguNGMwLjYsMS44LDEuOSwzLjMsMy43LDQuMXYtMS42Yy0yLjUtMS41LTMuNC00LjctMS45LTcuMmMwLjctMS4zLDItMi4yLDMuNC0yLjVsMC42LTAuMQoJbDAtMC42YzAtMC4yLDAtMC40LDAtMC42YzAtNC4zLDMuNS03LjcsNy44LTcuN2MzLjYsMCw2LjgsMi41LDcuNiw2bDAuMSwwLjZsMC42LTAuMWMwLjIsMCwwLjUsMCwwLjcsMGMzLjYsMCw2LjUsMi45LDYuNSw2LjUKCWMwLDEuOS0wLjgsMy43LTIuMiw0Ljl2MS44YzIuMy0xLjQsMy43LTMuOSwzLjctNi42QzMxLjEsMTQuOCwyNy41LDExLjMsMjMuMiwxMS4zeiIvPgo8cGF0aCBjbGFzcz0ic3QyIiBkPSJNMS4yLDEyLjJjMCwwLTAuMSwwLTAuMSwwYy0wLjQtMC4xLTAuNi0wLjQtMC42LTAuOEMxLjcsNC45LDcuNCwwLjIsMTQsMC4yYzMuMSwwLDYuMiwxLjEsOC42LDMKCWMwLjksMC43LDEuNiwxLjUsMi4zLDIuM2MwLjIsMC4zLDAuMiwwLjgtMC4xLDFjLTAuMywwLjItMC44LDAuMi0xLTAuMWMtMC42LTAuOC0xLjMtMS41LTItMi4xYy0yLjItMS44LTUtMi43LTcuOC0yLjcKCWMtNiwwLTExLjEsNC4yLTEyLjIsMTBDMS44LDEyLDEuNSwxMi4yLDEuMiwxMi4yeiBNMTguMywxOGMtMC40LDAtMC43LDAuMy0wLjgsMC43YzAsMC40LDAuMywwLjcsMC43LDAuOGMwLDAsMCwwLDAuMSwwaDMuOQoJbC04LjUsOC4xYy0wLjMsMC4zLTAuMywwLjcsMCwxYzAuMywwLjMsMC43LDAuMywxLDBsOC41LTh2My45YzAsMC40LDAuNCwwLjcsMC44LDAuN2MwLjQsMCwwLjctMC4zLDAuNy0wLjdWMThMMTguMywxOEwxOC4zLDE4egoJIE0xNC43LDIzLjFWMThIOS42Yy0wLjQsMC0wLjcsMC40LTAuNywwLjhjMCwwLjQsMC4zLDAuNywwLjcsMC43aDIuNkw3LDI0LjJjLTAuMywwLjMtMC4zLDAuNywwLDFjMC4zLDAuMywwLjcsMC4zLDEsMGw1LjItNC44djIuNwoJYzAsMC40LDAuNCwwLjcsMC44LDAuN0MxNC40LDIzLjgsMTQuNywyMy41LDE0LjcsMjMuMUwxNC43LDIzLjF6IE0xOC44LDI4LjZjMCwwLjQsMC4zLDAuNywwLjcsMC43aDIuN2wtNC43LDUuMQoJYy0wLjMsMC4zLTAuMywwLjcsMCwxYzAuMywwLjMsMC43LDAuMywxLDBjMCwwLDAsMCwwLjEtMC4xbDQuNi01VjMzYzAsMC40LDAuMywwLjcsMC43LDAuOGMwLjQsMCwwLjctMC4zLDAuOC0wLjdjMCwwLDAsMCwwLTAuMQoJdi01LjFoLTUuMUMxOS4xLDI3LjksMTguOCwyOC4yLDE4LjgsMjguNkwxOC44LDI4LjZ6Ii8+Cjwvc3ZnPgo=" alt="VMware Cloud Foundation"/>
                                </cds-icon>
                                <span class="title">VMware Cloud Foundation</span>
                            </a>
                        </div>
                    </header>
    '
    $clarityCssHeader += $clarityCssShared
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
                        <li><a class="nav-link" href="#esxi-license">Licensing Health</a></li>
                        <li><a class="nav-link" href="#esxi-disk">Disk Health</a></li>
                        <li><a class="nav-link" href="#esxi-connection">Connection Health</a></li>
                        <li><a class="nav-link" href="#esxi-free-pool">Free Pool Health</a></li>
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
                        <li><a class="nav-link" href="#nsx-tn-tunnel">NSX Transport Node Tunnels</a></li>
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
                        <li><a class="nav-link" href="#storage-vm-cdrom">Connected CD-ROMs</a></li>
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
                <section class="nav-group collapsible">
                    <input id="vcenter" type="checkbox"/>
                    <label for="vcenter">vCenter Server</label>
                    <ul class="nav-list">
                        <li><a class="nav-link" href="#cluster-config">Cluster Configuration</a></li>
                        <li><a class="nav-link" href="#cluster-drs-rules">vSphere DRS Rules</a></li>
                        <li><a class="nav-link" href="#cluster-resource-pools">Resource Pools</a></li>
                        <li><a class="nav-link" href="#cluster-overrides">VM Overrides</a></li>
                        <li><a class="nav-link" href="#cluster-networks">Virtual Networks</a></li>
                    </ul>
                </section>
                <section class="nav-group collapsible">
                    <input id="esxi" type="checkbox"/>
                    <label for="esxi">ESXi Hosts</label>
                    <ul class="nav-list">
                        <li><a class="nav-link" href="#esxi-security">Security Configuration</a></li>
                    </ul>
                </section>
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
        $formatOutput = ($dfOutput.ScriptOutput -split '\r?\n').Trim() -replace '(^\s+|\s+$)', '' -replace '\s+', ' '

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
                    # 'Invoke-SddcCommand -server <SDDC_Manager_FQDN> -user <administrator@vsphere.local> -pass <administrator@vsphere.local_password> -GuestUser root -vmPass <SDDC_Manager_RootPassword> -command "du -Sh <mount-point> | sort -rh | head -10" '
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
    $oldAddLine = ':-: '
    $newNewLine = '<br/>'

    $htmlData = $htmlData -replace $oldAlertOK,$newAlertOK
    $htmlData = $htmlData -replace $oldAlertCritical,$newAlertCritical
    $htmlData = $htmlData -replace $oldAlertWarning,$newAlertWarning
    $htmlData = $htmlData -replace $oldTable,$newTable
    $htmlData = $htmlData -replace $oldAddLine,$newNewLine
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
        [Parameter (Mandatory = $true)] [ValidateSet("SDDC","vCenter","NSX Manager","NSX Edge","vRSLCM","vRLI","vROPS","vRA","WSA")] [String]$component
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

##############################  End Supporting Functions ###############################
########################################################################################
