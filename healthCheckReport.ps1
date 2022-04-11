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
    Write-LogMessage -Type INFO -Message "Preparing the Formatting for the final HTML report"
    $reportFormat = Get-DefaultHtmlReportStyle # Get the default CSS style for formatting the HTML report
    $reportTitle = "<h1>Health Check Report for SDDC Manager: $sddcManagerFqdn</h1>" # Define the Report Tile
    Write-LogMessage -Type INFO -Message "Executing SoS Health Check Collection on VMware Cloud Foundation Instance ($sddcManagerFqdn), process takes time"
    # if ($PsBoundParameters.ContainsKey("allDomains")) { 
    #     $jsonFilePath = Request-SoSHealthJson -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -rootPass $sddcManagerRootPass -reportPath $reportFolder -allDomains
    # } elseif ($PsBoundParameters.ContainsKey("workloadDomain")) {
    #     $jsonFilePath = Request-SoSHealthJson -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -rootPass $sddcManagerRootPass -reportPath $reportFolder -workloadDomain $workloadDomain
    # }

    $sosHealthTitle = "<h2>SoS Health Check Data</h2>" # Define SoS Health Title
    Write-LogMessage -Type INFO -Message "Generating the Service Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
    Write-LogMessage -Type INFO -Message "Generating the DNS Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
    Write-LogMessage -Type INFO -Message "Generating the NTP Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
    Write-LogMessage -Type INFO -Message "Generating the Certificate Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
    #Write-LogMessage -Type INFO -Message "Generating the Password Expiry Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
    Write-LogMessage -Type INFO -Message "Generating the ESXi Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
    Write-LogMessage -Type INFO -Message "Generating the VSAN Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
    Write-LogMessage -Type INFO -Message "Generating the VSAN Storage Policy Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
    Write-LogMessage -Type INFO -Message "Generating the vCenter Server Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
    Write-LogMessage -Type INFO -Message "Generating the NSX-T Data Center Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
    Write-LogMessage -Type INFO -Message "Generating the Connectivity Health Report from SoS Output on SDDC Manager ($sddcManagerFqdn)"
    if ($PsBoundParameters.ContainsKey("failureOnly")) {
        $serviceHtml = Publish-ServiceHealth -json $jsonFilePath -html -failureOnly
        $dnsHtml = Publish-DnsHealth -json $jsonFilePath -html -failureOnly
        $ntpHtml = Publish-NtpHealth -json $jsonFilePath -html -failureOnly
        $certificateHtml = Publish-CertificateHealth -json $jsonFilePath -html -failureOnly
        #$passwordHtml = Publish-PasswordHealth -json $jsonFilePath -html -failureOnly
        $esxiHtml = Publish-EsxiHealth -json $jsonFilePath -html -failureOnly
        $vsanHtml = Publish-VsanHealth -json $jsonFilePath -html -failureOnly
        $vsanPolicyHtml = Publish-VsanStoragePolicy -json $jsonFilePath -html -failureOnly
        $vcenterHtml = Publish-VcenterHealth -json $jsonFilePath -html -failureOnly
        $nsxtHtml = Publish-NsxtHealth -json $jsonFilePath -html -failureOnly
        $connectivityHtml = Publish-ConnectivityHealth -json $jsonFilePath -html -failureOnly
    } else {
        $serviceHtml = Publish-ServiceHealth -json $jsonFilePath -html
        $dnsHtml = Publish-DnsHealth -json $jsonFilePath -html
        $ntpHtml = Publish-NtpHealth -json $jsonFilePath -html
        $certificateHtml = Publish-CertificateHealth -json $jsonFilePath -html
        #$passwordHtml = Publish-PasswordHealth -json $jsonFilePath -html
        $esxiHtml = Publish-EsxiHealth -json $jsonFilePath -html
        $vsanHtml = Publish-VsanHealth -json $jsonFilePath -html
        $vsanPolicyHtml = Publish-VsanStoragePolicy -json $jsonFilePath -html
        $vcenterHtml = Publish-VcenterHealth -json $jsonFilePath -html
        $nsxtHtml = Publish-NsxtHealth -json $jsonFilePath -html
        $connectivityHtml = Publish-ConnectivityHealth -json $jsonFilePath -html
    }
    # Combine all SoS Health Reports into single variable for consumption when generating the report
    $sosHealthHtml = "$sosHealthTitle $serviceHtml $dnsHtml $ntpHtml $certificateHtml $passwordHtml $esxiHtml $vsanHtml $vsanPolicyHtml $vcenterHtml $nsxtHtml $connectivityHtml"

    # Generating the Password Expiry Report
    # TO DO: Wrapper Function to be called here
    Write-LogMessage -Type INFO -Message "Generating the Password Expiry Report from SDDC Manager ($sddcManagerFqdn)"
    $allPasswordExpiryObject = New-Object System.Collections.ArrayList
    $sddcPasswordExpiry = Request-SddcManagerUserExpiry -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -rootPass $sddcManagerRootPass; $allPasswordExpiryObject += $sddcPasswordExpiry
    $vcenterPasswordExpiry = Request-vCenterUserExpiry -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass; $allPasswordExpiryObject += $vcenterPasswordExpiry
    $vrslcmPasswordExpiry = Request-vRslcmUserExpiry -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass; $allPasswordExpiryObject += $vrslcmPasswordExpiry
    $allPasswordExpiryObject = $allPasswordExpiryObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h2>Password Expiry Health Status</h2>" -As Table
    $allPasswordExpiryObject = Convert-AlertClass -htmldata $allPasswordExpiryObject

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
    $report = ConvertTo-HTML -Body "$reportTitle $allPasswordExpiryObject $sosHealthHtml $backupUserHtml $datastoreTitle $allStorageCapacityHtml $coreDumpTitle $allEsxiCoreDumpHtml" -Title "SDDC Manager Health Check Report" -Head $reportFormat -PostContent "<p>Creation Date: $(Get-Date)<p>"

    # Generate the report to an HTML file and then open it in the default browser
    Write-LogMessage -Type INFO -Message "Generating the Final Report and Saving to ($reportName)"
    $report | Out-File $reportName
    Invoke-Item $reportName
}
Catch {
    Debug-CatchWriter -object $_
}

