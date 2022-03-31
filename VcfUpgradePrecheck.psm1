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
        if (!(Test-Path $json)) {
            Write-Error "Unable to find JSON file at location ($json)" -ErrorAction Stop
        }
        else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }
        $htmlPreContent = "<h3>Service Health Status</h3>"
        $outputObject = New-Object System.Collections.ArrayList
        $inputData = $targetContent.'Services'
        foreach ($component in $inputData) {
            foreach ($element in $component.PsObject.Properties.Value) {
                $elementObject = New-Object -TypeName psobject
                $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue ($element.area -Split (":"))[0].Trim()
                $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
                $elementObject | Add-Member -notepropertyname 'Service Name' -notepropertyvalue $element.title.ToUpper()
                #$elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
                $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
                $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
                if ($PsBoundParameters.ContainsKey("failureOnly")) {
                    if (($element.status -eq "FAILED")) {
                        $outputObject += $elementObject
                    }
                }
                else {
                    $outputObject += $elementObject
                }
            }
        }
        if ($PsBoundParameters.ContainsKey("html")) { 
            $outputObject | Sort-Object Component, Resource, 'Service Name' | ConvertTo-Html -Fragment -PreContent $htmlPreContent -As Table
        }
        else {
            $outputObject | Sort-Object Component, Resource, 'Service Name' 
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
        if (!(Test-Path $json)) {
            Write-Error "Unable to find JSON file at location ($json)" -ErrorAction Stop
        }
        else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }
        # Collect DNS Forward Lookup Health data from SOS JSON
        $htmlPreContentForward = "<h3>DNS Forward Lookup Health Status</h3>"
        $allForwardLookupObject = New-Object System.Collections.ArrayList
        $inputData = $targetContent.'DNS lookup Status'.'Forward lookup Status'
        foreach ($element in $inputData.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue ($element.area -Split (":"))[0].Trim()
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
            #$elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $allForwardLookupObject += $elementObject
                }
            }
            else {
                $allForwardLookupObject += $elementObject
            }
        }
        # Collect DNS Revers Lookup Health data from SOS JSON
        $htmlPreContentReverse = "<h3>DNS Reverse Lookup Health Status</h3>"
        $allReverseLookupObject = New-Object System.Collections.ArrayList
        $reverseLookup = $targetContent.'DNS lookup Status'.'Reverse lookup Status'
        foreach ($element in $inputData.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue ($element.area -Split (":"))[0].Trim()
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
            #$elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $allReverseLookupObject += $elementObject
                }
            }
            else {
                $allReverseLookupObject += $elementObject
            }
        }
        if ($PsBoundParameters.ContainsKey("html")) { 
            $allForwardLookupObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent $htmlPreContentForward -As Table
            $allReverseLookupObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent $htmlPreContentReverse -As Table
        }
        else {
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
        if (!(Test-Path $json)) {
            Write-Error "Unable to find JSON file at location ($json)" -ErrorAction Stop
        }
        else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }
        # Extract data from the provided SOS JSON Health Check file
        $htmlPreContent = "<h3>NTP Health Status</h3>"
        $jsonInputData = $targetContent.'NTP'
        $jsonInputData.PSObject.Properties.Remove('ESXi HW Time')
        $jsonInputData.PSObject.Properties.Remove('ESXi Time')
        # Run the extracted data through the Read-JsonElement function to structure the data for report output
        if ($PsBoundParameters.ContainsKey("failureOnly")) {
            $outputObject = Read-JsonElement -inputData $jsonInputData -failureOnly
        }
        else {
            $outputObject = Read-JsonElement -inputData $jsonInputData
        }
        # Return the structured data to the console or format using HTML CSS Styles
        if ($PsBoundParameters.ContainsKey("html")) { 
            $outputObject = $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent $htmlPreContent -As Table
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
        if (!(Test-Path $json)) {
            Write-Error "Unable to find JSON file at location ($json)" -ErrorAction Stop
        }
        else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }
        $htmlPreContent = "<h3>Certificate Health Status</h3>"
        $outputObject = New-Object System.Collections.ArrayList
        # Collect Certificat Health data from SOS JSON for everything but ESXi
        $inputData = $targetContent.'Certificates'.'Certificate Status'
        $inputData.PSObject.Properties.Remove('ESXI')
        foreach ($component in $inputData.PsObject.Properties.Value) { 
            foreach ($element in $component.PsObject.Properties.Value) { 
                $elementObject = New-Object -TypeName psobject
                $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue ($element.area -Split (":"))[0].Trim()
                $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
                #$elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
                $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
                $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
                if ($PsBoundParameters.ContainsKey("failureOnly")) {
                    if (($element.status -eq "FAILED")) {
                        $outputObject += $elementObject
                    }
                }
                else {
                    $outputObject += $elementObject
                }
            }
        }
        # Collect Certificat Health data from SOS JSON for ESXi
        $inputData = $targetContent.'Certificates'.'Certificate Status'.ESXI
        foreach ($element in $inputData.PsObject.Properties.Value) { 
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue ($element.area -Split (":"))[0].Trim()
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
            #$elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $outputObject += $elementObject
                }
            }
            else {
                $outputObject += $elementObject
            }
        }

        if ($PsBoundParameters.ContainsKey("html")) { 
            $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent $htmlPreContent -As Table
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
        if (!(Test-Path $json)) {
            Write-Error "Unable to find JSON file at location ($json)" -ErrorAction Stop
        }
        else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }
        $htmlPreContent = "<h3>Password Health Status</h3>"
        $outputObject = New-Object System.Collections.ArrayList
        $inputData = $targetContent.'Password Expiry Status'
        foreach ($element in $inputData.PsObject.Properties.Value) { 
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue ($element.area -Split (":"))[0].Trim()
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
            #$elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $outputObject += $elementObject
                }
            }
            else {
                $outputObject += $elementObject
            }
        }

        if ($PsBoundParameters.ContainsKey("html")) { 
            $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent $htmlPreContent -As Table
        }
        else {
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
        if (!(Test-Path $json)) {
            Write-Error "Unable to find JSON file at location ($json)" -ErrorAction Stop
        }
        else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }
        # Collect ESXi Overall Health Status from SOS JSON 
        $htmlPreContentOverall = "<h3>ESXi Overall Health Status</h3>"
        $allOverallDumpObject = New-Object System.Collections.ArrayList
        $inputData = $targetContent.Compute.'ESXi Overall Health'
        foreach ($element in $inputData.PsObject.Properties.Value) { 
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue ($element.area -Split (":"))[0].Trim()
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
            #$elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $allOverallDumpObject += $elementObject
                }
            }
            else {
                $allOverallDumpObject += $elementObject
            }
        }
        # Collect ESXi Core Dump Health Status from SOS JSON
        $htmlPreContentCoreDump = "<h3>ESXi Core Dump Health Status</h3>"
        $allCoreDumpObject = New-Object System.Collections.ArrayList
        $inputData = $targetContent.General.'ESXi Core Dump Status'
        foreach ($element in $inputData.PsObject.Properties.Value) { 
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue ($element.area -Split (":"))[0].Trim()
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
            #$elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $allCoreDumpObject += $elementObject
                }
            }
            else {
                $allCoreDumpObject += $elementObject
            }
        }
        # Collect ESXi License Health Status from SOS JSON
        $htmlPreContentLicense = "<h3>ESXi License Health Status</h3>"
        $allLicenseObject = New-Object System.Collections.ArrayList
        $inputData = $targetContent.Compute.'ESXi License Status'
        foreach ($element in $inputData.PsObject.Properties.Value) { 
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue ($element.area -Split (":"))[0].Trim()
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
            #$elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $allLicenseObject += $elementObject
                }
            }
            else {
                $allLicenseObject += $elementObject
            }
        }
        # Collect ESXi Disk Health Status from SOS JSON
        $htmlPreContentDisk = "<h3>ESXi Disk Health Status</h3>"
        $allDiskObject = New-Object System.Collections.ArrayList
        $inputData = $targetContent.Compute.'ESXi Disk Status'
        foreach ($element in $inputData.PsObject.Properties.Value) { 
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue ($element.area -Split (":"))[0].Trim()
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
            #$elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $allDiskObject += $elementObject
                }
            }
            else {
                $allDiskObject += $elementObject
            }
        }

        if ($PsBoundParameters.ContainsKey("html")) {
            $allOverallDumpObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent $htmlPreContentOverall -As Table
            $allCoreDumpObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent $htmlPreContentCoreDump -As Table
            $allLicenseObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent $htmlPreContentLicense -As Table
            $allDiskObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent $htmlPreContentDisk -As Table
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
        if (!(Test-Path $json)) {
            Write-Error "Unable to find JSON file at location ($json)" -ErrorAction Stop
        }
        else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }
        $outputObject = New-Object System.Collections.ArrayList # Define the object for all data
        # Collect VSAN Cluster Health Statusfrom SOS JSON
        $htmlPreContent = "<h3>VSAN Cluster Health Status</h3>"
        $inputData = $targetContent.VSAN.'Cluster vSAN Status' # Extract specific data from all data read in from the JSON file
        foreach ($element in $inputData.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue (($element.area -Split (" : "))[1].Trim() -Split (" - "))[0]
            $elementObject | Add-Member -notepropertyname 'Cluster' -notepropertyvalue ($element.area -Split ("Cluster : "))[-1]
            $elementObject | Add-Member -notepropertyname 'Check' -notepropertyvalue $element.title
            #$elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $outputObject += $elementObject
                }
            }
            else {
                $outputObject += $elementObject
            }
        }
        $inputData = $targetContent.VSAN.'Cluster Disk Status' # Extract specific data from all data read in from the JSON file
        foreach ($element in $inputData.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue (($element.area -Split (" : "))[1].Trim() -Split (" - "))[0]
            $elementObject | Add-Member -notepropertyname 'Cluster' -notepropertyvalue ($element.area -Split ("Cluster : "))[-1]
            $elementObject | Add-Member -notepropertyname 'Check' -notepropertyvalue $element.title
            #$elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $outputObject += $elementObject
                }
            }
            else {
                $outputObject += $elementObject
            }
        }
        $inputData = $targetContent.VSAN.'Cluster Data Compression Status' # Extract specific data from all data read in from the JSON file
        foreach ($element in $inputData.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue (($element.area -Split (" : "))[1].Trim() -Split (" - "))[0]
            $elementObject | Add-Member -notepropertyname 'Cluster' -notepropertyvalue ($element.area -Split ("Cluster : "))[-1]
            $elementObject | Add-Member -notepropertyname 'Check' -notepropertyvalue $element.title
            #$elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $outputObject += $elementObject
                }
            }
            else {
                $outputObject += $elementObject
            }
        }
        $inputData = $targetContent.VSAN.'Cluster Data Encryption Status' # Extract specific data from all data read in from the JSON file
        foreach ($element in $inputData.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue (($element.area -Split (" : "))[1].Trim() -Split (" - "))[0]
            $elementObject | Add-Member -notepropertyname 'Check' -notepropertyvalue $element.title
            #$elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $outputObject += $elementObject
                }
            }
            else {
                $outputObject += $elementObject
            }
        }
        $inputData = $targetContent.VSAN.'Cluster Data Deduplication Status' # Extract specific data from all data read in from the JSON file
        foreach ($element in $inputData.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue (($element.area -Split (" : "))[1].Trim() -Split (" - "))[0]
            $elementObject | Add-Member -notepropertyname 'Check' -notepropertyvalue $element.title
            #$elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $outputObject += $elementObject
                }
            }
            else {
                $outputObject += $elementObject
            }
        }
        $inputData = $targetContent.VSAN.'Stretched Cluster Status' # Extract specific data from all data read in from the JSON file
        foreach ($element in $inputData.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue (($element.area -Split (" : "))[1].Trim() -Split (" - "))[0]
            $elementObject | Add-Member -notepropertyname 'Check' -notepropertyvalue $element.title
            #$elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $outputObject += $elementObject
                }
            }
            else {
                $outputObject += $elementObject
            }
        }
        if ($PsBoundParameters.ContainsKey("html")) { 
            $outputObject | Sort-Object Resource, Cluster, 'Check' | ConvertTo-Html -Fragment -PreContent $htmlPreContent -As Table
        }
        else {
            $outputObject | Sort-Object Resource, Cluster, 'Check' 
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
        Formats Password Health data from SoS output JSON

        .DESCRIPTION
        The Publish-NsxtHealth cmdlets formats the Password Health data from the SoS output JSON so that it can be consume
        either as a standard powershell object or an HTML based object for reporting purposes. 

        .EXAMPLE
        Publish-NsxtHealth -json <file-name>
        This example uses the JSON file provided to extracts the Password Health data and formats as a powershell object

        .EXAMPLE
        Publish-NsxtHealth -json <file-name> -html
        This example uses the JSON file provided to extracts the Password Health data and formats as an HTML object
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$json,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$failureOnly
    )

    Try {
        if (!(Test-Path $json)) {
            Write-Error "Unable to find JSON file at location ($json)" -ErrorAction Stop
        }
        else {
            $targetContent = Get-Content $json | ConvertFrom-Json
        }
        $htmlPreContent = "<h3>NSX-T Health Status</h3>"
        $outputObject = New-Object System.Collections.ArrayList
        # Collect NSX Manager Health data from SOS JSON
        $component = "NSX Manager"
        $inputData = $targetContent.General.'NSX Health'.'NSX Manager'
        foreach ($element in $inputData.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue $component
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
            #$elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $outputObject += $elementObject
                }
            }
            else {
                $outputObject += $elementObject
            }
        }
        # Collect NSX Container Cluster Health Status data from SOS JSON
        $component = "NSX Container Cluster"
        $inputData = $targetContent.General.'NSX Health'.'NSX Container Cluster Health Status'
        foreach ($element in $inputData.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue $component
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
            #$elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $outputObject += $elementObject
                }
            }
            else {
                $outputObject += $elementObject
            }
        }
        # Collect NSX Cluster Status data from SOS JSON
        $component = "NSX Cluster Status"
        $inputData = $targetContent.General.'NSX Health'.'NSX Cluster Status'
        foreach ($resource in $inputData.PsObject.Properties.Value) {
            foreach ($element in $resource.PsObject.Properties.Value) {
                $elementObject = New-Object -TypeName psobject
                $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue $component
                $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
                #$elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
                $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
                $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
                if ($PsBoundParameters.ContainsKey("failureOnly")) {
                    if (($element.status -eq "FAILED")) {
                        $outputObject += $elementObject
                    }
                }
                else {
                    $outputObject += $elementObject
                }
            }
        }

        if ($PsBoundParameters.ContainsKey("html")) { 
            $outputObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent $htmlPreContent -As Table
        }
        else {
            $outputObject | Sort-Object Component, Resource 
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-NsxtHealth


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

Function Show-SddcManagerLocalUser {
        <#
		.SYNOPSIS
        Check the status of a local account on SDDC Manager

        .DESCRIPTION
        The Show-SddcManagerLocalUser cmdlets checks the status of the local user on the SDDC Manager appliance.

        .EXAMPLE
        Show-SddcManagerLocalUser -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -rootPass VMw@re1! -localUser backup
        This example executes the command provided on the SDDC Manager appliance
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$rootPass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$localUser,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$html
    )
    
    Try {
        $command = 'chage -l ' + $localuser
        $htmlPreContent = '<h2>SDDC Manager Local User Report</h2>'
        $output = Invoke-SddcCommand -server $server -user $user -pass $pass -rootPass $rootPass -command $command
        $formatOutput = ($output.ScriptOutput -split '\r?\n').Trim()
        $formatOutput = $formatOutput -replace '(^\s+|\s+$)', '' -replace '\s+', ' '

        # Get the current date and expiration date
        Add-Type  -AssemblyName  Microsoft.VisualBasic
        $endDate = ($formatOutput[1] -Split (':'))[1].Trim()
        $expiryDays = [math]::Ceiling((([DateTime]$endDate) - (Get-Date)).TotalDays)

        # Set the status of the local user account based on the expiry date
        if ($expiryDays -le 15) {
            $status = 'YELLOW'  # Warning: <= 15 days
        }
        if ($expiryDays -le 7) {
            $status = 'RED'     # Critical: <= 7 days
        }
        else {
            $status = 'GREEN'   # OK: > 15 days
        }

        # Generate the results
        $userReport = New-Object -TypeName psobject
        $userReport | Add-Member -NotePropertyName 'User' -NotePropertyValue $localUser
        $userReport | Add-Member -NotePropertyName 'Password Expires' -NotePropertyValue ($formatOutput[1] -Split (':'))[1].Trim()
        $userReport | Add-Member -NotePropertyName 'Password Days Remaining' -NotePropertyValue $expiryDays     
        $userReport | Add-Member -NotePropertyName 'Account Expires' -NotePropertyValue ($formatOutput[3] -Split (':'))[1].Trim()
        $userReport | Add-Member -NotePropertyName 'Status' -NotePropertyValue $status

        # Output the results to HTML
        if ($PsBoundParameters.ContainsKey('html')) { 
            $userReport | ConvertTo-Html -Fragment -PreContent $htmlPreContent -As Table
        }
        # Output the results to the console
        else {
            $userReport
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Show-SddcManagerLocalUser

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

##########################################  E N D   O F   F U N C T I O N S  ##########################################
#######################################################################################################################


#########################################################################################
#############################  Start Supporting Functions  ##############################

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
                }
            }
        }
    }
}
Export-ModuleMember -Function Invoke-SddcCommand

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
    h1 { font-family: Arial, Helvetica, sans-serif; color: #1A4288; font-size: 30px; }
    h2 { font-family: Arial, Helvetica, sans-serif; color: #459B36; font-size: 20px; }
    h3 { font-family: Arial, Helvetica, sans-serif; color: #7F35B2; font-size: 16px; }
    body { font-family: Arial, Helvetica, sans-serif; color: #464547; font-size: 12px; }
    table { font-size: 12px; border: 0px;  font-family: monospace; } 
    td { padding: 4px; margin: 0px; border: 0; }
    th { background: #717074; background: linear-gradient(#464547, #717074); color: #fff; font-size: 11px; text-transform: capitalize; padding: 10px 15px; vertical-align: middle; }
    tbody tr:nth-child(even) { background: #f0f0f2; }
    #CreationDate { font-family: Arial, Helvetica, sans-serif; color: #ff3300; font-size: 12px; }
    .alertOK { color: #78BE20; border: 0px; font-family: Arial, Helvetica, sans-serif; font-size: 12px; font-weight: bold}
    .alertWarning { color: #EC7700; border: 0px; font-family: Arial, Helvetica, sans-serif; font-size: 12px; font-weight: bold}
    .alertCritical { color: #9F2842; border: 0px; font-family: Arial, Helvetica, sans-serif; font-size: 12px; font-weight: bold}
    .statusPass { color: #78BE20; border: 0px; font-family: Arial, Helvetica, sans-serif; font-size: 12px; font-weight: bold}
    .statusFail { color: #9F2842; border: 0px; font-family: Arial, Helvetica, sans-serif; font-size: 12px; font-weight: bold}
</style>
"@
$defaultCssStyle
}
Export-ModuleMember -Function Get-DefaultHtmlReportStyle

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

##############################  End Supporting Functions ###############################
########################################################################################


#########################################################################################
##############################  Start Internal Functions  ###############################

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

    # Function to replace Alerts with colour coded CSS Stylea
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

###############################  End Internal Functions ################################
########################################################################################
