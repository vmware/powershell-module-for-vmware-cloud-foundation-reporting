# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### Note
# This PowerShell module should be considered entirely experimental. It is still in development & not tested beyond lab
# scenarios. It is recommended you don't use it for any production environment without testing extensively!

# Enable communication with self signed certs when using Powershell Core. If you require all communications to be secure
# and do not wish to allow communication with self-signed certificates remove lines 13-36 before importing the module.

if ($PSEdition -eq 'Core') {
    $PSDefaultParameterValues.Add("Invoke-RestMethod:SkipCertificateCheck", $true)
}

if ($PSEdition -eq 'Desktop') {
    # Enable communication with self signed certs when using Windows Powershell
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
        Execute SoS and Retrive the JSON File

        .DESCRIPTION
        The Request-SoSHealthJson cmdlets connects to SDDC Manager, triggers SoS Health collection to JSON and then
        downloads the JSON file to the local file system

        .EXAMPLE
        Request-SoSHealthJson -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -rootPass VMw@re1! -reportPath F:\Precheck\HealthReports -allDomains
        This example uses the JSON file provided to extracts the Service Health data and formats as a powershell object

        .EXAMPLE
        
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$rootPass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$reportPath,
        [Parameter (ParameterSetName = 'All-WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [Switch]$allDomains,
        [Parameter (ParameterSetName = 'Specific--WorkloadDomains', Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$workloadDomain
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

Function Publish-ServiceHealth {
    <#
        .SYNOPSIS
        Formats Service Health data from SoS output JSON

        .DESCRIPTION
        The Publish-ServiceHealth cmdlets formats the Service Health data from the SoS output JSON so that it can be consume
        either as a standard powershell object or an HTML based object for reporting purposes. 

        .EXAMPLE
        Publish-ServiceHealth -json <file-name>
        This example uses the JSON file provided to extracts the Service Health data and formats as a powershell object

        .EXAMPLE
        Publish-ServiceHealth -json <file-name> -html
        This example uses the JSON file provided to extracts the Service Health data and formats as an HTML object
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

        $outputObject = New-Object System.Collections.ArrayList
        $inputData = $targetContent.'Services' # Extract Data from the provided SOS JSON
        foreach ($component in $inputData) {
            foreach ($element in $component.PsObject.Properties.Value) {
                $elementObject = New-Object -TypeName psobject
                $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue ($element.area -Split (":"))[0].Trim()
                $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
                $elementObject | Add-Member -notepropertyname 'Service Name' -notepropertyvalue $element.title.ToUpper()
                $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
                $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
                if ($PsBoundParameters.ContainsKey("failureOnly")) {
                    if (($element.status -eq "FAILED")) {
                        $outputObject += $elementObject
                    }
                } else {
                    $outputObject += $elementObject
                }
            }
        }

        if ($PsBoundParameters.ContainsKey("html")) { 
            $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>Service Health Status</h3>" -As Table
            $outputObject = Convert-AlertClass -htmldata $outputObject
            $outputObject
        } else {
            $outputObject | Sort-Object Component, Resource 
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-ServiceHealth

Function Publish-DnsHealth {
    <#
        .SYNOPSIS
        Formats DNS Health data from SoS output JSON

        .DESCRIPTION
        The Publish-DnsHealth cmdlets formats the DNS Health data from the SoS output JSON so that it can be consume
        either as a standard powershell object or an HTML based object for reporting purposes. 

        .EXAMPLE
        Publish-DnsHealth -json <file-name>
        This example uses the JSON file provided to extracts the DNS Health data and formats as a powershell object

        .EXAMPLE
        Publish-DnsHealth -json <file-name> -html
        This example uses the JSON file provided to extracts the DNS Health data and formats as an HTML object
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
            $allForwardLookupObject = Convert-AlertClass -htmldata $allForwardLookupObject
            $allForwardLookupObject
            $allReverseLookupObject =$allReverseLookupObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>DNS Reverse Lookup Health Status</h3>" -As Table
            $allReverseLookupObject = Convert-AlertClass -htmldata $allReverseLookupObject
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

Function Publish-NtpHealth {
    <#
        .SYNOPSIS
        Formats NTP Health data from SoS output JSON

        .DESCRIPTION
        The Publish-NtpHealth cmdlets formats the NTP Health data from the SoS output JSON so that it can be consume
        either as a standard powershell object or an HTML based object for reporting purposes. 

        .EXAMPLE
        Publish-NtpHealth -json <file-name>
        This example uses the JSON file provided to extracts the NTP Health data and formats as a powershell object

        .EXAMPLE
        Publish-NtpHealth -json <file-name> -html
        This example uses the JSON file provided to extracts the NTP Health data and formats as an HTML object
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
            $outputObject = Convert-AlertClass -htmldata $outputObject
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

Function Publish-CertificateHealth {
    <#
        .SYNOPSIS
        Formats Certificate Health data from SoS output JSON

        .DESCRIPTION
        The Publish-CertificateHealth cmdlets formats the Certificate Health data from the SoS output JSON so that it can be consume
        either as a standard powershell object or an HTML based object for reporting purposes. 

        .EXAMPLE
        Publish-CertificateHealth -json <file-name>
        This example uses the JSON file provided to extracts the Certificate Health data and formats as a powershell object

        .EXAMPLE
        Publish-CertificateHealth -json <file-name> -html
        This example uses the JSON file provided to extracts the Certificate Health data and formats as an HTML object
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

        # ESXi Certificate Health
        $jsonInputData = $targetContent.'Certificates'.'Certificate Status'.ESXi # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }
        
        # Certificate Health (Except ESXi)
        $customObject = New-Object System.Collections.ArrayList
        $inputData = $targetContent.'Certificates'.'Certificate Status' # Extract Data from the provided SOS JSON
        $inputData.PSObject.Properties.Remove('ESXI')
        foreach ($component in $inputData.PsObject.Properties.Value) { 
            foreach ($element in $component.PsObject.Properties.Value) { 
                $elementObject = New-Object -TypeName psobject
                $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue ($element.area -Split (":"))[0].Trim()
                $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
                $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
                $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
                if ($PsBoundParameters.ContainsKey("failureOnly")) {
                    if (($element.status -eq "FAILED")) {
                        $customObject += $elementObject
                    }
                } else {
                    $customObject += $elementObject
                }
            }
        }

        $outputObject += $customObject # Combined ESXi Certificate Health with Remaining Components

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) { 
            $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>Certificate Health Status</h3>" -As Table
            $outputObject = Convert-AlertClass -htmldata $outputObject
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

Function Publish-PasswordHealth {
    <#
        .SYNOPSIS
        Formats Password Health data from SoS output JSON

        .DESCRIPTION
        The Publish-PasswordHealth cmdlets formats the Password Health data from the SoS output JSON so that it can be consume
        either as a standard powershell object or an HTML based object for reporting purposes. 

        .EXAMPLE
        Publish-PasswordHealth -json <file-name>
        This example uses the JSON file provided to extracts the Password Health data and formats as a powershell object

        .EXAMPLE
        Publish-PasswordHealth -json <file-name> -html
        This example uses the JSON file provided to extracts the Password Health data and formats as an HTML object
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
            $outputObject = Convert-AlertClass -htmldata $outputObject
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

Function Publish-EsxiHealth {
    <#
        .SYNOPSIS
        Formats ESXi Health data from SoS output JSON

        .DESCRIPTION
        The Publish-EsxiHealth cmdlets formats the ESXi Health data from the SoS output JSON so that it can be consume
        either as a standard powershell object or an HTML based object for reporting purposes. 

        .EXAMPLE
        Publish-EsxiHealth -json <file-name>
        This example uses the JSON file provided to extracts the ESXi Health data and formats as a powershell object

        .EXAMPLE
        Publish-EsxiHealth -json <file-name> -html
        This example uses the JSON file provided to extracts the ESXi Health data and formats as an HTML object
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

        # ESXi Overall Health Status
        $allOverallHealthObject = New-Object System.Collections.ArrayList
        $jsonInputData = $targetContent.Compute.'ESXi Overall Health' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $allOverallHealthObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $allOverallHealthObject = Read-JsonElement -inputData $jsonInputData
        }

        # ESXi Core Dump Status
        $allCoreDumpObject = New-Object System.Collections.ArrayList
        $jsonInputData = $targetContent.General.'ESXi Core Dump Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $allCoreDumpObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $allCoreDumpObject = Read-JsonElement -inputData $jsonInputData
        }
        
        # ESXi License Status
        $allLicenseObject = New-Object System.Collections.ArrayList
        $jsonInputData = $targetContent.Compute.'ESXi License Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $allLicenseObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $allLicenseObject = Read-JsonElement -inputData $jsonInputData
        }

        # ESXi Disk Status
        $allDiskObject = New-Object System.Collections.ArrayList
        $jsonInputData = $targetContent.Compute.'ESXi Disk Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $allDiskObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $allDiskObject = Read-JsonElement -inputData $jsonInputData
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) { 
            $allOverallHealthObject = $allOverallHealthObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>ESXi Overall Health Status</h3>" -As Table;
            $allOverallHealthObject = Convert-AlertClass -htmldata $allOverallHealthObject
            $allOverallHealthObject
            $allCoreDumpObject = $allCoreDumpObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>ESXi Core Dump Health Status</h3>" -As Table
            $allCoreDumpObject = Convert-AlertClass -htmldata $allCoreDumpObject
            $allCoreDumpObject
            $allLicenseObject = $allLicenseObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>ESXi License Health Status</h3>" -As Table
            $allLicenseObject = Convert-AlertClass -htmldata $allLicenseObject
            $allLicenseObject
            $allDiskObject= $allDiskObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>ESXi Disk Health Status</h3>" -As Table
            $allDiskObject = Convert-AlertClass -htmldata $allDiskObject
            $allDiskObject
        } else {
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

Function Publish-VsanHealth {
    <#
        .SYNOPSIS
        Formats VSAN Health data from SoS output JSON

        .DESCRIPTION
        The Publish-VsanHealth cmdlets formats the VSAN Health data from the SoS output JSON so that it can be consume
        either as a standard powershell object or an HTML based object for reporting purposes. 

        .EXAMPLE
        Publish-VsanHealth -json <file-name>
        This example uses the JSON file provided to extracts the VSAN Health data and formats as a powershell object

        .EXAMPLE
        Publish-VsanHealth -json <file-name> -html
        This example uses the JSON file provided to extracts the VSAN Health data and formats as an HTML object
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
        $customObject += $outputObject # Adding individual component to main customeObject
        
        # Cluster Disk Status
        $jsonInputData = $targetContent.VSAN.'Cluster Disk Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }
        $customObject += $outputObject # Adding individual component to main customeObject

        # Cluster Data Compression Status
        $jsonInputData = $targetContent.VSAN.'Cluster Data Compression Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }
        $customObject += $outputObject # Adding individual component to main customeObject

        # Cluster Data Encryption Status
        $jsonInputData = $targetContent.VSAN.'Cluster Data Encryption Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }
        $customObject += $outputObject # Adding individual component to main customeObject

        # Cluster Data Deduplication Status
        $jsonInputData = $targetContent.VSAN.'Cluster Data Deduplication Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }
        $customObject += $outputObject # Adding individual component to main customeObject

        # Stretched Cluster Status
        $jsonInputData = $targetContent.VSAN.'Stretched Cluster Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }
        $customObject += $outputObject # Adding individual component to main customeObject

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) { 
            $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>VSAN Health Status</h3>" -As Table
            $customObject = Convert-AlertClass -htmldata $customObject
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

Function Publish-NsxtHealth {
    <#
        .SYNOPSIS
        Formats NSX Health data from SoS output JSON

        .DESCRIPTION
        The Publish-NsxtHealth cmdlets formats the NSX Health data from the SoS output JSON so that it can be consume
        either as a standard powershell object or an HTML based object for reporting purposes. 

        .EXAMPLE
        Publish-NsxtHealth -json <file-name>
        This example uses the JSON file provided to extracts the NSX Health data and formats as a powershell object

        .EXAMPLE
        Publish-NsxtHealth -json <file-name> -html
        This example uses the JSON file provided to extracts the NSX Health data and formats as an HTML object
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
    
        # NSX Manager Health
        $component = "NSX Manager"
        $inputData = $targetContent.General.'NSX Health'.'NSX Manager'
        foreach ($element in $inputData.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue $component
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $customObject += $elementObject
                }
            } else {
                $customObject += $elementObject
            }
        }

        # NSX Container Cluster Health Status
        $component = "NSX Container Cluster"
        $inputData = $targetContent.General.'NSX Health'.'NSX Container Cluster Health Status'
        foreach ($element in $inputData.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue $component
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $customObject += $elementObject
                }
            } else {
                $customObject += $elementObject
            }
        }
        # NSX Cluster Status
        $component = "NSX Cluster Status"
        $inputData = $targetContent.General.'NSX Health'.'NSX Cluster Status'
        foreach ($resource in $inputData.PsObject.Properties.Value) {
            foreach ($element in $resource.PsObject.Properties.Value) {
                $elementObject = New-Object -TypeName psobject
                $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue $component
                $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
                $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
                $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
                if ($PsBoundParameters.ContainsKey("failureOnly")) {
                    if (($element.status -eq "FAILED")) {
                        $customObject += $elementObject
                    }
                } else {
                    $customObject += $elementObject
                }
            }
        }

        # NSX Edge Health
        $component = "NSX Edge"
        $inputData = $targetContent.General.'NSX Health'.'NSX Edge'
        foreach ($resource in $inputData.PsObject.Properties.Value) {
            foreach ($element in $resource.PsObject.Properties.Value) {
                $elementObject = New-Object -TypeName psobject
                $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue $component
                $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
                $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
                $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
                if ($PsBoundParameters.ContainsKey("failureOnly")) {
                    if (($element.status -eq "FAILED")) {
                        $customObject += $elementObject
                    }
                } else {
                    $customObject += $elementObject
                }
            }
        }

        # NSX Controllers Health
        $component = "NSX Controllers"
        $inputData = $targetContent.General.'NSX Health'.'NSX Controllers'
        foreach ($resource in $inputData.PsObject.Properties.Value) {
            foreach ($element in $resource.PsObject.Properties.Value) {
                $elementObject = New-Object -TypeName psobject
                $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue $component
                $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
                $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
                $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
                if ($PsBoundParameters.ContainsKey("failureOnly")) {
                    if (($element.status -eq "FAILED")) {
                        $customObject += $elementObject
                    }
                } else {
                    $customObject += $elementObject
                }
            }
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) { 
            $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>NSX-T Data Center Health Status</h3>" -As Table
            $customObject = Convert-AlertClass -htmldata $customObject
            $customObject
        } else {
            $customObject | Sort-Object Component, Resource 
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-NsxtHealth

Function Publish-VcenterHealth {
    <#
        .SYNOPSIS
        Formats vCenter Server Health data from SoS output JSON

        .DESCRIPTION
        The Publish-VcenterHealth cmdlets formats the vCenter Server Health data from the SoS output JSON so that it can be consume
        either as a standard powershell object or an HTML based object for reporting purposes. 

        .EXAMPLE
        Publish-VcenterHealth -json <file-name>
        This example uses the JSON file provided to extracts the vCenter Server Health data and formats as a powershell object

        .EXAMPLE
        Publish-VcenterHealth -json <file-name> -html
        This example uses the JSON file provided to extracts the vCenter Server Health data and formats as an HTML object
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
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) { 
            $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>vCenter Server Health Status</h3>" -As Table
            $outputObject = Convert-AlertClass -htmldata $outputObject
            $outputObject
        } else {
            $outputObject | Sort-Object Component, Resource 
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-VcenterHealth

Function Publish-ConnectivityHealth {
    <#
        .SYNOPSIS
        Formats Connectivity Health data from SoS output JSON

        .DESCRIPTION
        The Publish-ConnectivityHealth cmdlets formats the Connectivity Health data from the SoS output JSON so that it can be consume
        either as a standard powershell object or an HTML based object for reporting purposes. 

        .EXAMPLE
        Publish-ConnectivityHealth -json <file-name>
        This example uses the JSON file provided to extracts the Connectivity Health data and formats as a powershell object

        .EXAMPLE
        Publish-ConnectivityHealth -json <file-name> -html
        This example uses the JSON file provided to extracts the Connectivity Health data and formats as an HTML object
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
        # ESXi SSH Status
        $jsonInputData = $targetContent.Connectivity.'Connectivity Status'.'ESXi SSH Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }
        $customObject += $outputObject # Adding individual component to main customeObject

        # ESXi API Status
        $jsonInputData = $targetContent.Connectivity.'Connectivity Status'.'ESXi API Status' # Extract Data from the provided SOS JSON
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }
        $customObject += $outputObject # Adding individual component to main customeObject

        # Additional Items Status
        $jsonInputData = $targetContent.Connectivity.'Connectivity Status' # Extract Data from the provided SOS JSON
        $jsonInputData.PSObject.Properties.Remove('ESXi SSH Status')
        $jsonInputData.PSObject.Properties.Remove('ESXi API Status')
        if ($PsBoundParameters.ContainsKey("failureOnly")) { # Run the extracted data through the Read-JsonElement function to structure the data for report output
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        } else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }
        $customObject += $outputObject # Adding individual component to main customeObject

        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) { 
            $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>Connectivity Health Status</h3>" -As Table
            $customObject = Convert-AlertClass -htmldata $customObject
            $customObject
        } else {
            $customObject | Sort-Object Component, Resource 
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-ConnectivityHealth


##########################################  E N D   O F   F U N C T I O N S  ##########################################
#######################################################################################################################


#######################################################################################################################
####################################  H E A L T H   C H E C K   F U N C T I O N S   ###################################

Function Export-SystemPassword {
    <#
		.SYNOPSIS
        Generates a system password report 

        .DESCRIPTION
        The Export-SystemPassword cmdlets generates a system password report from SDDC Manager. The cmdlet connects to
        SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Generates a system password report from SDDC Manager and outputs to an HTML format

        .EXAMPLE
        Export-SystemPassword -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1!
        Export-SystemPassword -server ldn-vcf01.ldn.cloudy.io -user administrator@vsphere.local -pass VMw@re1!
        This example generates a system password report from SDDC Manager
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
        Generates a storage capacity report

        .DESCRIPTION
        The Export-EsxiCoreDumpConfig cmdlets generates a storage capacity report for a Workload Domain. The cmdlet
        connects to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Generates a storage capacity report for all clusters of the Workload Domain

        .EXAMPLE
        Export-EsxiCoreDumpConfig -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -sddcDomain sfo-m01
        Export-EsxiCoreDumpConfig -server ldn-vcf01.ldn.cloudy.io -user administrator@vsphere.local -pass VMw@re1! -sddcDomain ldn-m01
        This example generates a storage capacity report for the Workload Domain named 'sfo-m01'
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
                            $allHostObject | ConvertTo-Html -Fragment -PreContent "<h3>ESXi Core Dump Configurtion for Workload Domain $sddcDomain</h3>" -As Table
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
        Generates a storage capacity report

        .DESCRIPTION
        The Export-StorageCapacity cmdlets generates a storage capacity report for a Workload Domain. The cmdlet
        connects to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Generates a storage capacity report for all clusters of the Workload Domain

        .EXAMPLE
        Export-StorageCapacity -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -sddcDomain sfo-m01
        Export-StorageCapacity -server ldn-vcf01.ldn.cloudy.io -user administrator@vsphere.local -pass VMw@re1! -sddcDomain ldn-m01
        This example generates a storage capacity report for the Workload Domain named 'sfo-m01'
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

Function Request-SddcManagerUserExpiry {
    <#
		.SYNOPSIS
        Checks user expiry

        .DESCRIPTION
        The Request-SddcManagerUserExpiry cmdlets checks additional user expiry details across a VMWare Cloud Foundation instance
        where the SoS Health Check does not. The cmdlet connects to SDDC Manager using the -server, -user, and
        -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Performs checks on the user and outputs the results

        .EXAMPLE
        Request-SddcManagerUserExpiry -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -rootPass VMw@re1!
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$rootPass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html
    )

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
                            $customObject = Convert-AlertClass -htmldata $customObject
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
Export-ModuleMember -Function Request-SddcManagerUserExpiry


Function Request-vCenterUserExpiry {
    <#
		.SYNOPSIS
        Checks vCenter Server local user expiry

        .DESCRIPTION
        The Request-vCenterUserExpiry cmdlets checks the expiry date of local accounts on vCenter Server. The cmdlet 
        connects to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Gathers the details for each vCenter Server
        - Collects information for the local root account
        - Checks when the password will expire and outputs the results

        .EXAMPLE
        Request-vCenterUserExpiry -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1!
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
                        $customObject = New-Object System.Collections.ArrayList
                        $allVcenters = Get-VCFvCenter
                        foreach ($vcenter in $allVcenters) {
                            $rootPass = (Get-VCFCredential | Where-Object {$_.credentialType -eq "SSH" -and $_.resource.resourceName -eq $vcenter.fqdn}).password
                            $elementObject = Request-LocalUserExpiry -fqdn $vcenter.fqdn -component vCenter -rootPass $rootPass -checkUser root
                            $customObject += $elementObject
                        }

                        # Return the structured data to the console or format using HTML CSS Styles
                        if ($PsBoundParameters.ContainsKey("html")) { 
                            $customObject = $customObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h2>Password Expiry Health Status</h2>" -As Table
                            $customObject = Convert-AlertClass -htmldata $customObject
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
Export-ModuleMember -Function Request-vCenterUserExpiry

Function Request-vRslcmUserExpiry {
    <#
		.SYNOPSIS
        Checks vCenter Server local user expiry

        .DESCRIPTION
        The Request-vRslcmUserExpiry cmdlets checks the expiry date of local accounts on vCenter Server. The cmdlet 
        connects to SDDC Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the vCenter Server instance
        - Gathers the details for each vCenter Server
        - Collects information for the local root account
        - Checks when the password will expire and outputs the results

        .EXAMPLE
        Request-vRslcmUserExpiry -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1!
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
                                $customObject = Convert-AlertClass -htmldata $customObject
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
        Execute a command on SDDC Manager

        .DESCRIPTION
        The Invoke-SddcCommand cmdlets executes a command within the SDDC Manager appliance. The cmdlet connects to SDDC
        Manager using the -server, -user, and -password values:
        - Validates that network connectivity is available to the SDDC Manager instance
        - Validates that network connectivity is available to the Management Domain vCenter Server instance
        - Executes the command provided within the SDDC Manager appliance

        .EXAMPLE
        Invoke-SddcCommand -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -rootPass VMw@re1! -command "chage -l backup"
        This example executes the command provided on the SDDC Manager appliance
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

Function Get-DefaultHtmlReportStyle {
# Define the default Cascading Style Sheets (CSS) for the HTML report
$defaultCssStyle = @"
<style>
    h1 { font-family: Metropolis, Arial, Helvetica, sans-serif; color: #1A4288; font-size: 30px; }
    h2 { font-family: Metropolis, Arial, Helvetica, sans-serif; color: #459B36; font-size: 20px; }
    h3 { ffont-family: Metropolis, Arial, Helvetica, sans-serif; color: #7F35B2; font-size: 16px; }
    body { font-family: Arial, Helvetica, sans-serif; color: #464547; font-size: 12px; }
    table { font-size: 12px; border: 0px;  font-family: monospace; } 
    td { padding: 4px; margin: 0px; border: 0; }
    th { background: #717074; background: linear-gradient(#464547, #717074); color: #fff; font-size: 11px; text-transform: capitalize; padding: 10px 15px; vertical-align: middle; }
    tbody tr:nth-child(even) { background: #f0f0f2; }
    #CreationDate { font-family: Metropolis, Arial, Helvetica, sans-serif; color: #ff3300; font-size: 12px; }
    .alertOK { color: #78BE20; border: 0px; font-family: Metropolis, Arial, Helvetica, sans-serif; font-size: 12px; font-weight: bold}
    .alertWarning { color: #EC7700; border: 0px; font-family: Metropolis, Arial, Helvetica, sans-serif; font-size: 12px; font-weight: bold}
    .alertCritical { color: #9F2842; border: 0px; font-family: Metropolis, Arial, Helvetica, sans-serif; font-size: 12px; font-weight: bold}
    .statusPass { color: #78BE20; border: 0px; font-family: Metropolis, Arial, Helvetica, sans-serif; font-size: 12px; font-weight: bold}
    .statusFail { color: #9F2842; border: 0px; font-family: Metropolis, Arial, Helvetica, sans-serif; font-size: 12px; font-weight: bold}
</style>
"@
$defaultCssStyle
}
Export-ModuleMember -Function Get-DefaultHtmlReportStyle

Function PercentCalc {
    Param (
        [Parameter (Mandatory = $true)] [Int]$InputNum1,
        [Parameter (Mandatory = $true)] [Int]$InputNum2)
        $InputNum1 / $InputNum2*100
}

Function Convert-AlertClass {
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

    $htmlData = $htmlData -replace $oldAlertOK,$newAlertOK
    $htmlData = $htmlData -replace $oldAlertCritical,$newAlertCritical
    $htmlData = $htmlData -replace $oldAlertWarning,$newAlertWarning
    $htmlData
}
Export-ModuleMember -Function Convert-AlertClass

Function Request-LocalUserExpiry {
    <#
        .SYNOPSIS
        Check the expiry of a local linux user

        .DESCRIPTION
        The Request-LocalUserExpiry cmdlets checks the expiry details of a local user on a linux operating system and
        outputs the data.

        .EXAMPLE
        Request-LocalUserExpiry -vmName sfo-vcf01.sfo.rainpole.io -rootPass VMw@re1! -component SDDC -checkUser backup
        This example executes the command to check the expiration status of the backup user 
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$fqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$rootPass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$checkUser,
        [Parameter (Mandatory = $true)] [ValidateSet("SDDC","vCenter","vRSLCM")] [String]$component
    )

    Try {
        if (Get-VM -Name ($server.Split(".")[0])) {
            $command = 'chage -l ' + $checkUser
            $output = Invoke-VMScript -VM ($server.Split(".")[0]) -ScriptText $command -GuestUser root -GuestPassword $rootPass
            $formatOutput = ($output.ScriptOutput -split '\r?\n').Trim()
            $formatOutput = $formatOutput -replace '(^\s+|\s+$)', '' -replace '\s+', ' '

            # Get the current date and expiration date
            Add-Type  -AssemblyName  Microsoft.VisualBasic
            $endDate = ($formatOutput[1] -Split (':'))[1].Trim()
            $expiryDays = [math]::Ceiling((([DateTime]$endDate) - (Get-Date)).TotalDays)

            # Set the status of the local user account based on the expiry date
            if ($expiryDays -le 15) {
                $alert = 'YELLOW'  # Warning: <= 15 days
                $message = "Password will expire in 15 or lese days. Verfied using $command"
            }
            if ($expiryDays -le 5) {
                $alert = 'RED'     # Critical: <= 5 days
                $message = "Password will expiration in less than 5 days or has already expired. Verfied using $command"
            } else {
                $alert = 'GREEN'   # OK: > 15 days
                $message = "Password will not expire within the next 15 days. Verfied using $command"
            }

            $userObject = New-Object -TypeName psobject
            $userObject | Add-Member -notepropertyname 'Component' -notepropertyvalue $component
            $userObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue $fqdn
            $userObject | Add-Member -notepropertyname 'User' -notepropertyvalue $checkUser
            $userObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $alert
            $userObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $message
            $userObject
        } else {
            Write-Error "Unable to locate Virtual Machine ($($server.Split(".")[0])) in the vCenter Server inventory, check details"
        }

    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Request-LocalUserExpiry

##############################  End Supporting Functions ###############################
########################################################################################