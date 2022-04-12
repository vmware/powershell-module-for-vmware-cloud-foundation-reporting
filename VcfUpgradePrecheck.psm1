# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### Note
# This PowerShell module should be considered entirely experimental. It is still in development & not tested beyond lab
# scenarios. It is recommended you don't use it for any production environment without testing extensively!

# Allow communication with self-signed certificates when using Powershell Core. If you require all communications to be
# secure and do not wish to allow communication with self-signed certificates, remove lines 13-36 before importing the
# module.

if ($PSEdition -eq 'Core') {
    $PSDefaultParameterValues.Add("Invoke-RestMethod:SkipCertificateCheck", $true)
}

if ($PSEdition -eq 'Desktop') {
    # Allow communication with self-signed certificates when using Windows Powershell
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
#############################  S O S   J S O N   E X T R A C T I O N   F U N C T I O N S   ############################

Function Request-SoSHealthJson {
    <#
        .SYNOPSIS
        Run SoS and save the JSON output.

        .DESCRIPTION
        The Request-SoSHealthJson cmdlet connects to SDDC Manager, runs an SoS Health collection to JSON, and saves the
        JSON file to the local file system.

        .EXAMPLE
        Request-SoSHealthJson -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -rootPass VMw@re1! -reportPath F:\Precheck\HealthReports -allDomains
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
            $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<h3>Certificate Health Status</h3>' -As Table
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
            $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<h3>Connectivity Health Status</h3>' -As Table
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
            $allForwardLookupObject = $allForwardLookupObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>DNS Forward Lookup Health Status</h3>" -As Table
            $allForwardLookupObject = Convert-CssClass -htmldata $allForwardLookupObject
            $allForwardLookupObject
            $allReverseLookupObject =$allReverseLookupObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>DNS Reverse Lookup Health Status</h3>" -As Table
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
            $allOverallHealthObject = $allOverallHealthObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<h3>ESXi Overall Health Status</h3>' -As Table;
            $allOverallHealthObject = Convert-CssClass -htmldata $allOverallHealthObject
            $allOverallHealthObject
            $allCoreDumpObject = $allCoreDumpObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<h3>ESXi Core Dump Health Status</h3>' -As Table
            $allCoreDumpObject = Convert-CssClass -htmldata $allCoreDumpObject
            $allCoreDumpObject
            $allLicenseObject = $allLicenseObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<h3>ESXi License Health Status</h3>' -As Table
            $allLicenseObject = Convert-CssClass -htmldata $allLicenseObject
            $allLicenseObject
            $allDiskObject = $allDiskObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<h3>ESXi Disk Health Status</h3>' -As Table
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

        # NSX Edge Health
        $component = 'NSX Edge'
        $inputData = $targetContent.General.'NSX Health'.'NSX Edge'
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
            $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<h3>NSX-T Data Center Health Status</h3>' -As Table
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
            $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>NTP Health Status</h3>" -As Table
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
            $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>Password Expiry Health Status</h3>" -As Table
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
            $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<h3>Service Health Status</h3>' -As Table
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
        }
        else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }

        # vCenter Overall Health
        $jsonInputData = $targetContent.Compute.'vCenter Overall Health' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey('failureOnly')) {
            # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        }
        else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey('html')) { 
            $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent '<h3>vCenter Server Health Status</h3>' -As Table
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
            $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>VSAN Health Status</h3>" -As Table
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
        Formats the vSAN Storage Policy for VM

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
            $outputObject = $outputObject | Sort-Object Component, 'vCenter Server', Resource | ConvertTo-Html -Fragment -PreContent "<h3>VSAN Storage Policy Health Status</h3>" -As Table
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

Function Export-SystemPassword {
    <#
		.SYNOPSIS
        Generates a system password report for an SDDC Manager instance.

        .DESCRIPTION
        The Export-SystemPassword cmdlets generates a system password report from SDDC Manager. The cmdlet connects to
        SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Generates a system password report from SDDC Manager and outputs to the console or HTML.

        .EXAMPLE
        Export-SystemPassword -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1!
        This example generates a system password report from SDDC Manager instance `sfo-vcf01.sfo.rainpole.io`.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html
    )
    $htmlPreContent = "<h2>System Passwords from SDDC Manager</h2>"
    if (Test-VCFConnection -server $server) {
        if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            if ($PsBoundParameters.ContainsKey("html")) {
                Get-VCFCredential | Select-Object @{Name="Workload Domain"; Expression={ $_.resource.domainName}}, @{Name="FQDN"; Expression={ $_.resource.resourceName}}, @{Name="IP Address"; Expression={ $_.resource.resourceIp}}, accountType, username, password | Where-Object {$_.accountType -eq "USER" -or $_.accountType -eq "SYSTEM"} | Sort-Object "Domain Name", "FQDN" | ConvertTo-Html -Fragment -PreContent $htmlPreContent -As Table
            }
            else {
                Get-VCFCredential | Select-Object @{Name="Workload Domain"; Expression={ $_.resource.domainName}}, @{Name="FQDN"; Expression={ $_.resource.resourceName}}, @{Name="IP Address"; Expression={ $_.resource.resourceIp}}, accountType, username, password | Where-Object {$_.accountType -eq "USER" -or $_.accountType -eq "SYSTEM"} | Sort-Object "Domain Name", "FQDN"
            }
        }
    }
}
Export-ModuleMember -Function Export-SystemPassword

Function Export-EsxiCoreDumpConfig {
    <#
		.SYNOPSIS
        Generates an ESXi core dump configuration report for a workload domain.

        .DESCRIPTION
        The Export-EsxiCoreDumpConfig cmdlet generates an ESXi core dump report for a workload domain. The cmdlet
        connects to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Generates an ESXi core dump report for all ESXi hosts in a workload domain

        .EXAMPLE
        Export-EsxiCoreDumpConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -sddcDomain sfo-w01
        This example generates an ESXi core dump report for all ESXi hosts in a workload domain named `sfo-w01`.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html
    )

    if (Test-VCFConnection -server $server) {
        if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $sddcDomain)) {
                if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                    if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                        $coreDumpObject = New-Object -TypeName psobject
                        $allHostObject = New-Object System.Collections.ArrayList
                        $esxiHosts = Get-VMHost 
                        Foreach ($esxiHost in $esxiHosts) {
                            $coreDumpObject = New-Object -TypeName psobject
                            $esxcli = Get-EsxCli -VMhost $esxiHost.Name -V2
                            $coreDumpConfig = $esxcli.system.coredump.partition.get.invoke()
                            $coreDumpObject | Add-Member -notepropertyname 'Host' -notepropertyvalue $esxiHost.Name
                            $coreDumpObject | Add-Member -notepropertyname 'Active Core Dump' -notepropertyvalue $coreDumpConfig.Active
                            $coreDumpObject | Add-Member -notepropertyname 'Configured Core Dump' -notepropertyvalue $coreDumpConfig.Configured
                            $allHostObject += $coreDumpObject
                        }
                        if ($PsBoundParameters.ContainsKey("html")) {
                            $allHostObject | ConvertTo-Html -Fragment -PreContent "<h3>ESXi Core Dump Configuration for Workload Domain $sddcDomain</h3>" -As Table
                        }
                        else {
                            $allHostObject
                        }
                    }
                    Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                }
            }
        }
    }
}
Export-ModuleMember -Function Export-EsxiCoreDumpConfig

Function Export-StorageCapacity {
    <#
		.SYNOPSIS
        Generates a storage capacity report for all clusters in a workload domain.

        .DESCRIPTION
        The Export-StorageCapacity cmdlet generates a storage capacity report for a workload domain. The cmdlet
        connects to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Generates a storage capacity report for all clusters in a workload domain

        .EXAMPLE
        Export-StorageCapacity -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -sddcDomain sfo-w01
        This example generates a storage capacity report for all clusters in a workload domain named 'sfo-w01'.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html
    )

    if (Test-VCFConnection -server $server) {
        if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $sddcDomain)) {
                if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                    if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                        $datastores = Get-Datastore | Sort-Object Name
                        Foreach ($datastore in $datastores) {
                            if (($datastore.Name -match "Shared") -or ($datastore.Name -match "")) {
                                $PercentFree = PercentCalc $datastore.FreeSpaceMB $datastore.CapacityMB
                                $PercentFree = "{0:N2}" -f $PercentFree
                                $datastore | Add-Member -type NoteProperty -name PercentFree -value $PercentFree
                            }
                        }
                        if ($PsBoundParameters.ContainsKey("html")) {
                            $datastores | Select-Object Name,@{N="Used Space GB";E={[Math]::Round(($_.ExtensionData.Summary.Capacity - $_.ExtensionData.Summary.FreeSpace)/1GB,0)}},@{N="Total Space GB";E={[Math]::Round(($_.ExtensionData.Summary.Capacity)/1GB,0)}} ,PercentFree | ConvertTo-Html -Fragment -PreContent "<h3>Datastore Storage Capacity for Workload Domain $sddcDomain</h3>" -As Table
                        }
                        else {
                            $datastores | Select-Object Name,@{N="Used Space GB";E={[Math]::Round(($_.ExtensionData.Summary.Capacity - $_.ExtensionData.Summary.FreeSpace)/1GB,0)}},@{N="Total Space GB";E={[Math]::Round(($_.ExtensionData.Summary.Capacity)/1GB,0)}} ,PercentFree
                        }
                    }
                    Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                }
            }
        }
    }
}
Export-ModuleMember -Function Export-StorageCapacity

Function Publish-LocalUserExpiry {
    <#
		.SYNOPSIS
        Request and publlish Local User Expiry

        .DESCRIPTION
        The Publish-LocalUserExpiry cmdlet checks the expiry for local users across the VMware Cloud Foundation
        instance and prepares the data to be published to an HTML report. The cmdlet connects to SDDC Manager using the
        -server, -user, and password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Performs checks on the local OS users and outputs the results

        .EXAMPLE
        Publish-LocalUserExpiry -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -sddcRootPass VMw@re1! -allDomains
        This example checks the expiry for local OS users in the SDDC Manager appliance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sddcRootPass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain
    )

    Try {

        $allPasswordExpiryObject = New-Object System.Collections.ArrayList
        $sddcPasswordExpiry = Request-SddcManagerUserExpiry -server $server -user $user -pass $pass -rootPass $sddcRootPass; $allPasswordExpiryObject += $sddcPasswordExpiry
        $vrslcmPasswordExpiry = Request-vRslcmUserExpiry -server $server -user $user -pass $pass; $allPasswordExpiryObject += $vrslcmPasswordExpiry
        if ($PsBoundParameters.ContainsKey("allDomains")) { 
            $vcenterPasswordExpiry = Request-vCenterUserExpiry -server $server -user $user -pass $pass -alldomains; $allPasswordExpiryObject += $vcenterPasswordExpiry
            $allWorkloadDomains = Get-VCFWorkloadDomain
            foreach ($domain in $allWorkloadDomains ) {
                $nsxtManagerPasswordExpiry = Request-NsxtManagerUserExpiry -server $server -user $user -pass $pass -domain $domain.name; $allPasswordExpiryObject += $nsxtManagerPasswordExpiry
                $nsxtEdgePasswordExpiry = Request-NsxtEdgeUserExpiry -server $server -user $user -pass $pass -domain $domain.name; $allPasswordExpiryObject += $nsxtEdgePasswordExpiry
            }
        }
        else {
            $vcenterPasswordExpiry = Request-vCenterUserExpiry -server $server -user $user -pass $pass -workloadDomain $workloadDomain; $allPasswordExpiryObject += $vcenterPasswordExpiry
            $nsxtManagerPasswordExpiry = Request-NsxtManagerUserExpiry -server $server -user $user -pass $pass -domain $workloadDomain; $allPasswordExpiryObject += $nsxtManagerPasswordExpiry
            $nsxtEdgePasswordExpiry = Request-NsxtEdgeUserExpiry -server $server -user $user -pass $pass -domain $workloadDomain; $allPasswordExpiryObject += $nsxtEdgePasswordExpiry
        }
        
        $allPasswordExpiryObject = $allPasswordExpiryObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>Password Expiry Health Status</h3>" -As Table
        $allPasswordExpiryObject = Convert-CssClass -htmldata $allPasswordExpiryObject
        $allPasswordExpiryObject
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-LocalUserExpiry

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
        Request-SddcManagerUserExpiry -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -rootPass VMw@re1!
        This example checks the expiry for additional local OS users in the SDDC Manager appliance.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$rootPass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html
    )

    Try {
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT)) {
                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            $customObject = New-Object System.Collections.ArrayList
                            $elementObject = Request-LocalUserExpiry -fqdn $server -component SDDC -rootPass $rootPass -checkUser backup
                            $customObject += $elementObject
                            $elementObject = Request-LocalUserExpiry -fqdn $server -component SDDC -rootPass $rootPass -checkUser root
                            $customObject += $elementObject
                            $elementObject = Request-LocalUserExpiry -fqdn $server -component SDDC -rootPass $rootPass -checkUser vcf
                            $customObject += $elementObject

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
        Request-NsxtEdgeUserExpiry -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01
        This example checks the expiry for local OS users for the NSX Edge node appliances for a specific workload domain.
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
                if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT)) {
                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            if (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $domain }) {
                                if (($vcfNsxDetails = Get-NsxtServerDetail -fqdn $server -username $user -password $pass -domain $domain)) {   
                                    if (($vcfNsxEdgeDetails = Get-VCFEdgeCluster | Where-Object { $_.nsxtCluster.vipFQDN -eq $vcfNsxDetails.fqdn })) {   
                                        $customObject = New-Object System.Collections.ArrayList
                                        foreach ($nsxtEdgeNode in $vcfNsxEdgeDetails.edgeNodes) {
                                            $rootPass = (Get-VCFCredential | Where-Object { $_.credentialType -eq 'SSH' -and $_.resource.resourceName -eq $vcfNsxDetails.fqdn }).password
                                            $elementObject = Request-LocalUserExpiry -fqdn $nsxtEdgeNode.hostname -component 'NSX Edge' -rootPass $rootPass -checkUser admin
                                            $customObject += $elementObject
                                            $elementObject = Request-LocalUserExpiry -fqdn $nsxtEdgeNode.hostname -component 'NSX Edge' -rootPass $rootPass -checkUser audit
                                            $customObject += $elementObject
                                            $elementObject = Request-LocalUserExpiry -fqdn $nsxtEdgeNode.hostname -component 'NSX Edge' -rootPass $rootPass -checkUser root
                                            $customObject += $elementObject
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
        Request-NsxtManagerUserExpiry -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01
        This example checks the expiry for local OS users for the NSX Manager appliances for a specific workload domain.
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
                if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domainType MANAGEMENT)) {
                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            if (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $domain }) {
                                if (($vcfNsxDetails = Get-NsxtServerDetail -fqdn $server -username $user -password $pass -domain $domain -listNodes)) {    
                                    $customObject = New-Object System.Collections.ArrayList
                                    foreach ($nsxtManagerNode in $vcfNsxDetails.nodes) {
                                        $rootPass = (Get-VCFCredential | Where-Object { $_.credentialType -eq 'SSH' -and $_.resource.resourceName -eq $vcfNsxDetails.fqdn }).password
                                        $elementObject = Request-LocalUserExpiry -fqdn $nsxtManagerNode.fqdn -component 'NSX Manager' -rootPass $rootPass -checkUser admin
                                        $customObject += $elementObject
                                        $elementObject = Request-LocalUserExpiry -fqdn $nsxtManagerNode.fqdn -component 'NSX Manager' -rootPass $rootPass -checkUser audit
                                        $customObject += $elementObject
                                        $elementObject = Request-LocalUserExpiry -fqdn $nsxtManagerNode.fqdn -component 'NSX Manager' -rootPass $rootPass -checkUser root
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
        Request-vCenterUserExpiry -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -allDomains
        This example will check the expiry date of the local OS 'root' account for all vCenter Server instances managed by SDDC Manager.

        .EXAMPLE
        Request-vCenterUserExpiry -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -workloadDomain sfo-w01
        This example will check the expiry date of the local OS 'root' account for a single workload domain
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html
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
                                    $customObject += $elementObject
                                }
                            }
                            else {
                                $vcenter = (Get-VCFWorkloadDomain | Where-Object {$_.name -eq $workloadDomain}).vcenters.fqdn
                                $rootPass = (Get-VCFCredential | Where-Object {$_.credentialType -eq "SSH" -and $_.resource.resourceName -eq $vcenter}).password
                                $elementObject = Request-LocalUserExpiry -fqdn $vcenter -component vCenter -rootPass $rootPass -checkUser root
                                $customObject += $elementObject
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
        Request-vRslcmUserExpiry -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1!
        This example will check the expiry date of the local OS 'root' account on the vRealize Suite Lifecycle Manager instance deployed by SDDC Manager.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html
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
                            $customObject = Request-LocalUserExpiry -fqdn $vrslcm.fqdn -component vRSLCM -rootPass $rootPass -checkUser root

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
        Request-SddcManagerBackupStatus -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1!
        This example will return the status of the latest file-level backup task in an SDDC Manager instance.
    #>

    # TO DO: Add support changing status based on age of backup.

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html
    )

    if (Test-VCFConnection -server $server) {
        if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            $backupTasks = Get-VCFTask | Where-Object { $_.type -eq 'SDDCMANAGER_BACKUP' } | Select-Object -First 1
            foreach ($backupTask in $backupTasks) {
                $component = 'SDDC Manager'
                $date = [DateTime]::ParseExact($backupTask.creationTimestamp, 'yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture)
                $domain = (Get-VCFWorkloadDomain | Sort-Object -Property type, name).name -join ','
                $resource = $backupTask.name + ": " + $server

                $customObject = New-Object -TypeName psobject
                $customObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component # Set the component name
                $customObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $resource # Set the name
                $customObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain # Set the domain(s)
                $customObject | Add-Member -NotePropertyName 'Date' -NotePropertyValue $date # Set the timestamp

                # Set the status for the backup task
                if ($backupTask.status -eq 'Successful') {                              
                    $customObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue 'GREEN' # Ok; success
                }
                else {
                    $customObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue 'RED' # Critical; failure
                }

                # Set the message for the backup task
                if ([string]::IsNullOrEmpty($errors)) {
                    $customObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue "The backup completed without errors."
                }
                else {
                    $customObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue 'The backup failed with errors. Please investigate before proceeding.'
                }
            }

            # Return the structured data to the console or format using HTML CSS Styles
            if ($PsBoundParameters.ContainsKey("html")) { 
                $customObject = $customObject | Sort-Object creationTimestamp, status | ConvertTo-Html -Fragment -PreContent '<h2>Backup Status</h2>' -As Table
                $customObject
            }
            else {
                $customObject | Sort-Object creationTimestamp
            }
        }
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
        Request-NsxtManagerBackupStatus -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-w01
        This example will return the status of the latest file-level backup of an NSX Manager cluster managed by SDDC Manager for a workload domain.
    #>

    # TO DO: Add support changing status based on age of backup.

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html
    )

    if (Test-VCFConnection -server $server) {
        if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            if (($vcfNsxDetails = Get-NsxtServerDetail -fqdn $server -username $user -password $pass -domain $domain)) {
                if (Test-NSXTConnection -server $vcfNsxDetails.fqdn) {
                    if (Test-NSXTAuthentication -server $vcfNsxDetails.fqdn -user $vcfNsxDetails.adminUser -pass $vcfNsxDetails.adminPass) {
                        $backupTask = Get-NsxtBackupHistory -fqdn $vcfNsxDetails.fqdn

                        $customObject = New-Object System.Collections.ArrayList

                        # NSX Node Backup
                        $component = 'NSX Manager'
                        $resource = 'Node: ' + $vcfNsxDetails.fqdn
                        foreach ($element in $backupTask.node_backup_statuses) {
                            $timestamp = [DateTimeOffset]::FromUnixTimeMilliseconds($backupTask.node_backup_statuses.end_time).DateTime

                            $elementObject = New-Object -TypeName psobject
                            $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component # Set the component name
                            $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $resource # Set the resource name
                            $elementObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain # Set the domain
                            $elementObject | Add-Member -NotePropertyName 'Date' -NotePropertyValue $timestamp # Set the end timestamp
                            if ($backupTask.node_backup_statuses.success -eq $true) {                              
                                $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue 'GREEN' # Ok; success
                                $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue 'The backup completed without errors.' # Set the backup status message
                            }
                            else {
                                $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue 'RED' # Critical; failure
                                $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue 'The backup failed with errors. Please investigate before proceeding.' # Set the backup status message
                            }
                        }

                        $customObject += $elementObject
                        
                        # NSX Cluster Backup
                        $component = 'NSX Manager'
                        $resource = 'Cluster: ' + $vcfNsxDetails.fqdn
                        foreach ($element in $backupTask.cluster_backup_statuses) {
                            $timestamp = [DateTimeOffset]::FromUnixTimeMilliseconds($backupTask.cluster_backup_statuses.end_time).DateTime

                            $elementObject = New-Object -TypeName psobject
                            $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component # Set the component name
                            $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $resource # Set the resource name
                            $elementObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain # Set the domain
                            $elementObject | Add-Member -NotePropertyName 'Date' -NotePropertyValue $timestamp # Set the end timestamp
                            if ($backupTask.node_backup_statuses.success -eq $true) {                              
                                $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue 'GREEN' # Ok; success
                                $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue 'The backup completed without errors.' # Set the backup status message
                            }
                            else {
                                $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue 'RED' # Critical; failure
                                $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue 'The backup failed with errors. Please investigate before proceeding.' # Set the backup status message
                            }
                        }

                        $customObject += $elementObject

                        # NSX Cluster Backup
                        $component = 'NSX Manager'
                        $resource = 'Inventory: ' + $vcfNsxDetails.fqdn
                        foreach ($element in $backupTask.cluster_backup_statuses) {
                            $timestamp = [DateTimeOffset]::FromUnixTimeMilliseconds($backupTask.cluster_backup_statuses.end_time).DateTime

                            $elementObject = New-Object -TypeName psobject
                            $elementObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component # Set the component name
                            $elementObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $resource # Set the resource name
                            $elementObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain # Set the domain
                            $elementObject | Add-Member -NotePropertyName 'Date' -NotePropertyValue $timestamp # Set the end timestamp
                            if ($backupTask.node_backup_statuses.success -eq $true) {                              
                                $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue 'GREEN' # Ok; success
                                $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue 'The backup completed without errors.' # Set the backup status message
                            }
                            else {
                                $elementObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue 'RED' # Critical; failure
                                $elementObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue 'The backup failed with errors. Please investigate before proceeding.' # Set the backup status message
                            }
                        }

                        $customObject += $elementObject

                        # Return the structured data to the console or format using HTML CSS Styles
                        if ($PsBoundParameters.ContainsKey('html')) { 
                            $customObject = $customObject | Sort-Object component, domain, resource, status | ConvertTo-Html -Fragment -PreContent '<h2>Backup Status</h2>' -As Table
                            $customObject
                        }
                        else {
                            $customObject | Sort-Object component, domain, resource, status
                        }
                        
                    }
                }
            }
        }
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
        Request-VcenterBackupStatus -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-w01
        This example will return the status of the latest file-level backup of a vCenter Server instance managed by SDDC Manager for a workload domain.
    #>

    # TO DO: Add support changing status based on age of backup.

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html
    )

    if (Test-VCFConnection -server $server) {
        if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            if (($vcfVcenterDetails = Get-VcenterServerDetail -server $server -user $user -pass $pass -domain $domain)) {
                if (Test-VsphereConnection -server $vcfVcenterDetails.fqdn) {
                    if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                        Connect-CisServer -server $vcfVcenterDetails.fqdn -username $vcfVcenterDetails.ssoAdmin -password $vcfVcenterDetails.ssoAdminPass | Out-Null
                        $backupTask = Get-VcenterBackupJobs | Select-Object -First 1 | Get-VcenterBackupStatus

                        $component = 'vCenter Server' # Set the component name
                        $date = $backupTask.end_time # Set the end timestamp
                        $resource = 'vCenter Server: ' + $vcfVcenterDetails.fqdn # Set the name of the resource

                        $customObject = New-Object -TypeName psobject
                        $customObject | Add-Member -NotePropertyName 'Component' -NotePropertyValue $component # Set the component name
                        $customObject | Add-Member -NotePropertyName 'Resource' -NotePropertyValue $resource # Set the resource name
                        $customObject | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domain # Set the domain(s)
                        $customObject | Add-Member -NotePropertyName 'Date' -NotePropertyValue $date # Set the timestamp

                        # Set the status for the backup task
                        if ($backupTask.state -eq 'SUCCEEDED') {                              
                            $customObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue 'GREEN' # Ok; success
                        }
                        elseif ($backupTask.state -eq 'IN PROGRESS') {                              
                            $customObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue 'YELLOW' # Warning; in progress
                        }
                        else {
                            $customObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue 'RED' # Critical; failure
                        }

                        # Set the message for the backup task
                        if ([string]::IsNullOrEmpty($messages)) {
                            $customObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue 'The backup completed without errors.'
                        }
                        else {
                            $customObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue 'The backup failed with errors. Please investigate before proceeding.'
                        }
                        
                        # Return the structured data to the console or format using HTML CSS Styles
                        if ($PsBoundParameters.ContainsKey('html')) { 
                            $customObject = $customObject | Sort-Object creationTimestamp, status | ConvertTo-Html -Fragment -PreContent '<h2>Backup Status</h2>' -As Table
                            $customObject
                        }
                        else {
                            $customObject | Sort-Object creationTimestamp
                        }
                        Disconnect-CisServer -Server $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue | Out-Null
                    }
                }
            }
        }
    }
}
Export-ModuleMember -Function Request-VcenterBackupStatus

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
    $greenThreshold = 70
    $redThreshold = 85

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
                { $_ -le $greenThreshold } {
                    # Green if $usage is up to $greenThreshold
                    $alert = 'GREEN'
                    $message = "Used space is less than $greenThreshold%. You could continue with the upgrade."
                }
                { $_ -ge $redThreshold } {
                    # Red if $usage is equal or above $redThreshold
                    $alert = 'RED'
                    $message = "Used space is above $redThreshold%. Please reclaim space on the partition before proceeding further."
                    # TODO Find how to display the message in html on multiple rows (Add <br> with the right escape chars)
                    # In order to display usage, you could run as root in SDDC Manager 'du -Sh <mount-point> | sort -rh | head -10' "
                    # As an alternative you could run PowerCLI commandlet:
                    # 'Invoke-SddcCommand -server <SDDC_Manager_FQDN> -user <administrator@vsphere.local> -pass <administrator@vsphere.local_password> -rootPass <SDDC_Manager_RootPassword> -command "du -Sh <mount-point> | sort -rh | head -10" '
                }
                Default {
                    # Yellow if above two are not matched
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
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }                        
                        
    # Return the structured data to the console or format using HTML CSS Styles
    if ($PsBoundParameters.ContainsKey("html")) { 
        $customObject = $customObject | ConvertTo-Html -Fragment -PreContent "<h2>SDDC Manager Disk Health Status</h2>" -As Table
        $customObject = Convert-CssClass -htmldata $customObject
    }
    # Return $customObject in HTML or pain format
    $customObject
    
}
Export-ModuleMember -Function Request-SddcManagerStorageHealth

##########################################  E N D   O F   F U N C T I O N S  ##########################################
#######################################################################################################################


#########################################################################################
#############################  Start Supporting Functions  ##############################

Function Start-CreateReportDirectory ($path, $sddcManagerFqdn) {
    $filetimeStamp = Get-Date -Format "MM-dd-yyyy_hh_mm_ss"
    $Global:reportFolder = $path + '\HealthReports\'
    if (!(Test-Path -Path $reportFolder)) {
        New-Item -Path $reportFolder -ItemType "directory" | Out-Null
    }
    $Global:reportName = $reportFolder + $sddcManagerFqdn.Split(".")[0] + "-healthCheck-" + $filetimeStamp + ".htm"
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
        Invoke-SddcCommand -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -rootPass VMw@re1! -command "chage -l backup"
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
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
    <html xmlns="http://www.w3.org/1999/xhtml">
    <head>
        <link rel="stylesheet" href="https://unpkg.com/@clr/ui/clr-ui.min.css" />
    <style>
        .alertOK { color: #78BE20; font-weight: bold}
        .alertWarning { color: #EC7700; font-weight: bold}
        .alertCritical { color: #9F2842; font-weight: bold}
    </style>
    </head>
    <body>
    <div class="clr-example">
    <div class="main-container">
        <header class="header-6">
        <div class="branding">
            <a href="javascript://">
            <cds-icon shape="vm-bug">
                <img src="icon.svg" alt="VMware Cloud Foundation"/>
            </cds-icon>
            <span class="title">PowerShell Module for VMware Cloud Foundation</span>
            </a>
        </div>
        <div class="settings">
            <a href="javascript://" class="nav-link nav-icon">
            <cds-icon shape="cog"></cds-icon>
            </a>
        </div>
        </header>
        <nav class="subnav">
        <ul class="nav">
            <li class="nav-item">
            <a class="nav-link active" href="javascript://">Health Check Report</a>
            </li>
        </ul>
        </nav>
        <div class="content-container">
        <div class="content-area">'
    $clarityCssHeader
}
Export-ModuleMember -Function Get-ClarityReportHeader

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
        [Parameter (Mandatory = $true)] [Int]$InputNum2)
        $InputNum1 / $InputNum2*100
}

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

Function Get-NsxtBackupHistory {
    <#
    SYNOPSIS:
    Return the backup history for an NSX Manager cluster.

    DESCRIPTION:
    The Get-NsxtBackupHistory cmdlet returns the backup history for an NSX Manager cluster

    EXAMPLE:
    Get-NsxtBackupHistory -fqdn sfo-w01-nsx01.sfo.rainpole.io
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
    Get-VcenterBackupJobs | Select -First 1 | Get-VCSABackupStatus
    This example demonstrates piping the results of this function into the Get-VcenterBackupStatus function..
    
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
                $snapshotObject = New-Object -TypeName psobject
                $snapshotObject | Add-Member -NotePropertyName 'Virtual Machine' -NotePropertyValue $name
                $snapshotObject | Add-Member -NotePropertyName 'Snapshot Name' -NotePropertyValue $snapshot.Name
                $snapshotObject | Add-Member -NotePropertyName 'Created' -NotePropertyValue $snapshot.Created
                $snapshotObject | Add-Member -NotePropertyName 'Current' -NotePropertyValue $snapshot.isCurrent
                $snapshotObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
                $snapshotObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue $message
                $snapshotObject | Sort-Object Created, isCurrent
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
                $message = "Consolidation is required."
            }
            else {
                $alert = 'GREEN' # OK: Consolidation not needed
                $message = "Consolidation is not required."
            }

            if ($snapshotCount -gt 1) {
                $messageAppend = "Use 'Get-SnapshotStatus -vm $vm' to review the status of each snapshot."
            }

            # Create a new PSObject to hold the results
            $outputObject = New-Object -TypeName psobject
            # Add the snapshot details to the PSObject
            $outputObject = New-Object -TypeName psobject
            $outputObject | Add-Member -NotePropertyName 'Virtual Machine' -NotePropertyValue $name
            $outputObject | Add-Member -NotePropertyName 'Snapshots' -NotePropertyValue $snapshotCount
            $outputObject | Add-Member -NotePropertyName 'Alert' -NotePropertyValue $alert
            $outputObject | Add-Member -NotePropertyName 'Message' -NotePropertyValue "$message $messageAppend"
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

##############################  End Supporting Functions ###############################
########################################################################################
