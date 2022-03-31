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
    The precheck.ps1 provides a single script to perform health checks across an SDDC Manager instance

    .EXAMPLE
    precheck.ps1 -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser administrator@vsphere.local -sddcManagerPass VMw@re1! -sddcManagerRootPass VMw@re1!
    This example performs multiple system prechecks for an SDDC Manager instance
#>

Param (
    [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerFqdn,
    [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerUser,
    [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerPass,
    [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcManagerRootPass,
    [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
)

$jsonFile = ".\SoS-JSON-HealthCheck-Samples\all-health-results.json" # TO DO: Function to generate and retrieve SOS JSON

Clear-Host; Write-Host ""

Start-SetupLogFile -Path $filePath -ScriptName $MyInvocation.MyCommand.Name
Write-LogMessage -Type INFO -Message "Starting the Process of Running Health Checks for VMware Cloud Foundation Instance ($sddcManagerFqdn)" -Colour Yellow
Write-LogMessage -Type INFO -Message "Setting up the log file to path $logfile"

# Setup the file name of the HTML based health check report
# TO DO: Function Required
$filetimeStamp = Get-Date -Format "MM-dd-yyyy_hh_mm_ss"
$reportLocation = ".\"
$reportFolder = "reports"
$reportsPath = $reportLocation + $reportFolder
if (!(Test-Path -Path $reportsPath)) {
    New-Item -Path $reportLocation -Name $reportFolder -ItemType "directory" | Out-Null
}
$reportName = $reportsPath + "\" + $sddcManagerFqdn.Split(".")[0] + "-healthCheck-" + $filetimeStamp + ".htm"

# Obtain the formatting of the HTML report using default CSS styles
$reportFormat = Get-DefaultHtmlReportStyle

# Define the Report Tile
$reportTitle = "<h1>Health Check Report for SDDC Manager: $sddcManagerFqdn</h1>"

$sosHealthTitle = "<h2>SoS Health Check Data</h2>" # Define SoS Health Title
Write-LogMessage -Type INFO -Message "Generating the Service Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
Write-LogMessage -Type INFO -Message "Generating the DNS Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
Write-LogMessage -Type INFO -Message "Generating the NTP Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
Write-LogMessage -Type INFO -Message "Generating the Certificate Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
Write-LogMessage -Type INFO -Message "Generating the Password Expiry Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
Write-LogMessage -Type INFO -Message "Generating the ESXi Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
Write-LogMessage -Type INFO -Message "Generating the VSAN Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
Write-LogMessage -Type INFO -Message "Generating the vCenter Server Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
Write-LogMessage -Type INFO -Message "Generating the NSX-T Data Center Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
if ($PsBoundParameters.ContainsKey("failureOnly")) {
    $serviceHtml = Publish-ServiceHealth -json $jsonFile -html -failureOnly
    $dnsHtml = Publish-DnsHealth -json $jsonFile -html -failureOnly
    $ntpHtml = Publish-NtpHealth -json $jsonFile -html -failureOnly
    $certificateHtml = Publish-CertificateHealth -json $jsonFile -html -failureOnly
    $passwordHtml = Publish-PasswordHealth -json $jsonFile -html -failureOnly
    $esxiHtml = Publish-EsxiHealth -json $jsonFile -html -failureOnly
    $vsanHtml = Publish-VsanHealth -json $jsonFile -html -failureOnly
    $vcenterHtml = Publish-VcenterHealth -json $jsonFile -html -failureOnly
    $nsxtHtml = Publish-NsxtHealth -json $jsonFile -html -failureOnly
} else {
    $serviceHtml = Publish-ServiceHealth -json $jsonFile -html
    $dnsHtml = Publish-DnsHealth -json $jsonFile -html
    $ntpHtml = Publish-NtpHealth -json $jsonFile -html
    $certificateHtml = Publish-CertificateHealth -json $jsonFile -html
    $passwordHtml = Publish-PasswordHealth -json $jsonFile -html
    $esxiHtml = Publish-EsxiHealth -json $jsonFile -html
    $vsanHtml = Publish-VsanHealth -json $jsonFile -html
    $vcenterHtml = Publish-VcenterHealth -json $jsonFile -html
    $nsxtHtml = Publish-NsxtHealth -json $jsonFile -html
}
# Combine all SoS Health Reports into single variable for consumption when generating the report
$sosHealthHtml = "$sosHealthTitle $serviceHtml $dnsHtml $ntpHtml $certificateHtml $passwordHtml $esxiHtml $vsanHtml $vcenterHtml $nsxtHtml"

# Generating the System Password Report from SDDC Manager 
Write-LogMessage -Type INFO -Message "Generating the System Password Report from SDDC Manager ($sddcManagerFqdn)"
$systemPasswordHtml = Export-SystemPassword -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -html

# # Check the Status of the Backup Account on the SDDC Manager Instance
# Write-LogMessage -Type INFO -Message "Check the Status of the Backup Account on SDDC Manager Appliance ($($sddcManagerFqdn.Split(".")[0]))"
# $backupUserHtml = Show-SddcManagerLocalUser -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -rootPass $sddcManagerRootPass -localUser backup -html

# $datastoreTitle = "<h2>Datastore Capacity for all Workload Domains</h2>"
# # Generating Datastore Capacity Report for all Workload Domains
# Write-LogMessage -Type INFO -Message "Generating Datastore Capacity Report for all Workload Domains"
# $allWorkloadDomain = Get-VCFWorkloadDomain | Select-Object name
# foreach ($workloadDomain in $allWorkloadDomain) {   
#     $storageCapacityHtml = Export-StorageCapacity -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -sddcDomain $workloadDomain.name -html
#     $allStorageCapacityHtml += $storageCapacityHtml
# }

# $coreDumpTitle = "<h2>ESXi Host Core Dump Configuration for all Workload Domains</h2>"
# # Generating ESXi Host Core Dump Configuaration for all Workload Domains
# Write-LogMessage -Type INFO -Message "Generating ESXi Host Core Dump Configuaration for all Workload Domains"
# $allWorkloadDomain = Get-VCFWorkloadDomain | Select-Object name
# foreach ($workloadDomain in $allWorkloadDomain) {
#     Write-LogMessage -Type INFO -Message "Gathering ESXi Host Core Dump Configuaration for Workload Domain ($($workloadDomain.name))"
#     $esxiCoreDumpHtml = Export-EsxiCoreDumpConfig -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -sddcDomain $workloadDomain.name -html
#     $allEsxiCoreDumpHtml += $esxiCoreDumpHtml
# }

# Combine all information gathered into a single HTML report
$report = ConvertTo-HTML -Body "$reportTitle $sosHealthHtml $backupUserHtml $systemPasswordHtml $datastoreTitle $allStorageCapacityHtml $coreDumpTitle $allEsxiCoreDumpHtml " -Title "SDDC Manager Health Check Report" -Head $reportFormat -PostContent "<p>Creation Date: $(Get-Date)<p>"

# Generate the report to an HTML file and then open it in the default browser
Write-LogMessage -Type INFO -Message "Generating the Final Report and Saving to ($reportName)"
$report | Out-File $reportName
Invoke-Item $reportName

