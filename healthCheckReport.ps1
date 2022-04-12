# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

<#
    .NOTES
    ===================================================================================================================
    Created by:  Gary Blake - Senior Staff Solutions Architect
    Date:   2022-03-29
    Copyright 2021-2022 VMware, Inc.
    ===================================================================================================================
    .CHANGE_LOG

    - 1.0.000   (Gary Blake / 2022-03-29) - Initial script creation

    ===================================================================================================================
    
    .SYNOPSIS
    Perform health checks across and SDDC Manager instance

    .DESCRIPTION
    The healthCheckReport.ps1 provides a single script to perform health checks across an SDDC Manager instance

    .EXAMPLE
    healthCheckReport.ps1 -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser administrator@vsphere.local -sddcManagerPass VMw@re1! -sddcManagerRootPass VMw@re1! -reportPath F:\Prechecks -allDomains
    This example performs multiple system prechecks for an SDDC Manager instance
#>

Param (
    [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerFqdn,
    [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerUser,
    [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerPass,
    [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerRootPass,
    [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$reportPath,
    [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
    [Parameter (ParameterSetName = 'Specific--WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
    [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
)

Try {
    Clear-Host; Write-Host ""

    Start-SetupLogFile -Path $reportPath -ScriptName $MyInvocation.MyCommand.Name # Setup Log Location and Log File
    Write-LogMessage -Type INFO -Message "Starting the Process of Running Health Checks for VMware Cloud Foundation Instance ($sddcManagerFqdn)" -Colour Yellow
    Write-LogMessage -Type INFO -Message "Setting up the log file to path $logfile"
    Start-CreateReportDirectory -path $reportPath -sddcManagerFqdn $sddcManagerFqdn # Setup Report Location and Report File
    Write-LogMessage -Type INFO -Message "Setting up report folder and report $reportName"

    Write-LogMessage -Type INFO -Message "Executing SoS Health Check Collection on VMware Cloud Foundation Instance ($sddcManagerFqdn), process takes time"
    # if ($PsBoundParameters.ContainsKey("allDomains")) { 
    #     $jsonFilePath = Request-SoSHealthJson -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -rootPass $sddcManagerRootPass -reportPath $reportFolder -allDomains
    # } elseif ($PsBoundParameters.ContainsKey("workloadDomain")) {
    #     $jsonFilePath = Request-SoSHealthJson -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -rootPass $sddcManagerRootPass -reportPath $reportFolder -workloadDomain $workloadDomain
    # }

    # Generating all SoS Health Data
    Write-LogMessage -Type INFO -Message "Generating the Service Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
    Write-LogMessage -Type INFO -Message "Generating the DNS Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
    Write-LogMessage -Type INFO -Message "Generating the NTP Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
    Write-LogMessage -Type INFO -Message "Generating the Certificate Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
    Write-LogMessage -Type INFO -Message "Generating the ESXi Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
    Write-LogMessage -Type INFO -Message "Generating the VSAN Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
    Write-LogMessage -Type INFO -Message "Generating the VSAN Storage Policy Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
    Write-LogMessage -Type INFO -Message "Generating the vCenter Server Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
    Write-LogMessage -Type INFO -Message "Generating the NSX-T Data Center Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
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
    }
    # Combine all SoS Health Reports into single variable for consumption when generating the report
    $sosHealthHtml = "$serviceHtml $dnsHtml $ntpHtml $certificateHtml $esxiHtml $vsanHtml $vsanPolicyHtml $vcenterHtml $nsxtHtml"

    # Generating the Connectivity Health Data
    Write-LogMessage -Type INFO -Message "Generating the Connectivity Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
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
    Write-LogMessage -Type INFO -Message "Generating the Backup Status Report from SDDC Manager ($sddcManagerFqdn)"
    if ($PsBoundParameters.ContainsKey("allDomains")) { 
        if ($PsBoundParameters.ContainsKey("failureOnly")) {
            # TODO: Backup needs to support -failureOnly switch
            # $backupStatusHtml = Publish-BackupStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains -failureOnly
        }
        else { 
            $backupStatusHtml = Publish-BackupStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -allDomains
        }
    }
    else {
        if ($PsBoundParameters.ContainsKey("failureOnly")) { 
            # TODO: Backup needs to support -failureOnly switch
            # $backupStatusHtml = Publish-BackupStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain -failureOnly
        }
        else {
            $backupStatusHtml = Publish-BackupStatus -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
        }
    }

    # Generating the Password Expiry Health Data
    Write-LogMessage -Type INFO -Message "Generating the Password Expiry Report from SDDC Manager ($sddcManagerFqdn)"
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

    # Generating the SDDC Manager disk usage report
    Write-LogMessage -Type INFO -Message "Generating the Disk Health Report from SDDC Manager ($sddcManagerFqdn)"
    $hddUsage = Request-SddcManagerStorageHealth -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -rootPass $sddcManagerRootPass
    $hddUsage = $hddUsage | ConvertTo-Html -Fragment -PreContent "<h3>SDDC Manager Disk Health Status</h3>" -As Table
    $hddUsage = Convert-CssClass -htmldata $hddUsage

    # Generating the Datastore disk usage report
    Write-LogMessage -Type INFO -Message "Generating the Datastore Usage Report from all vCenter Servers"
    $datastoreUsage = Request-DatastoreStorageCapacity -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass
    $datastoreUsage = $datastoreUsage | Sort-Object 'vCenter FQDN', 'Datastore Name' | ConvertTo-Html -Fragment -PreContent "<h3>Datastore Space Usage Report</h3>" -As Table
    $datastoreUsage = Convert-CssClass -htmldata $datastoreUsage

    # Combine all information gathered into a single HTML report
    $reportData = "$backupStatusHtml $localPasswordHtml $sosHealthHtml $componentConnectivityHtml $hddUsage $datastoreUsage"

    $reportHeader = Get-ClarityReportHeader
    $reportFooter = Get-ClarityReportFooter
    $report = $reportHeader
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

