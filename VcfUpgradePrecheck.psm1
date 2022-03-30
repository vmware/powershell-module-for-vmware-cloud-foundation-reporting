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

    if (Test-VCFConnection -server $server) {
        if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            if ($PsBoundParameters.ContainsKey("html")) {
                Get-VCFCredential | Select-Object @{Name="Workload Domain"; Expression={ $_.resource.domainName}}, @{Name="FQDN"; Expression={ $_.resource.resourceName}}, @{Name="IP Address"; Expression={ $_.resource.resourceIp}}, accountType, username, password | Where-Object {$_.accountType -eq "USER" -or $_.accountType -eq "SYSTEM"} | Sort-Object "Domain Name", "FQDN" | ConvertTo-Html -Fragment -PreContent "<h2>System Passwords from SDDC Manager</h2>" -As Table
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
        $htmlTitle = '<h2>SDDC Manager Local User Report</h2>'
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
            $userReport | ConvertTo-Html -Fragment -PreContent $htmlTitle -As Table
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
        $serviceData = $targetContent.'Services'
        $allServiceObject = New-Object System.Collections.ArrayList
        foreach ($service in $serviceData) {
            foreach ($element in $service.PsObject.Properties.Value) {
                $elementObject = New-Object -TypeName psobject
                $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue ($element.area -Split (":"))[0].Trim()
                $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
                $elementObject | Add-Member -notepropertyname 'Service Name' -notepropertyvalue $element.title.ToUpper()
                $elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
                $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
                $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
                if ($PsBoundParameters.ContainsKey("failureOnly")) {
                    if (($element.status -eq "FAILED")) {
                        $allServiceObject += $elementObject
                    }
                }
                else {
                    $allServiceObject += $elementObject
                }
            }
        }
        if ($PsBoundParameters.ContainsKey("html")) { 
            $allServiceObject | Sort-Object Component, Resource, 'Service Name' | ConvertTo-Html -Fragment -PreContent "<h3>Service Health Status</h3>" -As Table
        }
        else {
            $allServiceObject | Sort-Object Component, Resource, 'Service Name' 
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
        $forwaredLookup = $targetContent.'DNS lookup Status'.'Forward lookup Status'
        $allForwardLookupObject = New-Object System.Collections.ArrayList
        foreach ($element in $forwaredLookup.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue ($element.area -Split (":"))[0].Trim()
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
            $elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
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
        $reverseLookup = $targetContent.'DNS lookup Status'.'Reverse lookup Status'
        $allReverseLookupObject = New-Object System.Collections.ArrayList
        foreach ($element in $reverseLookup.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue ($element.area -Split (":"))[0].Trim()
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
            $elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
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
            $allForwardLookupObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>DNS Forward Lookup Health Status</h3>" -As Table
            $allReverseLookupObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>DNS Reverse Lookup Health Status</h3>" -As Table
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

        $ntpData = $targetContent.'NTP'
        $ntpData.PSObject.Properties.Remove('ESXi HW Time')
        $ntpData.PSObject.Properties.Remove('ESXi Time')
        $allNtpObject = New-Object System.Collections.ArrayList
        foreach ($element in $ntpData.PsObject.Properties.Value) { 
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Component' -notepropertyvalue ($element.area -Split (":"))[0].Trim()
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue ($element.area -Split (":"))[-1].Trim()
            $elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $allNtpObject += $elementObject
                }
            }
            else {
                $allNtpObject += $elementObject
            }
        }

        if ($PsBoundParameters.ContainsKey("html")) { 
            $allNtpObject | Sort-Object Component, Resource | ConvertTo-Html -Fragment -PreContent "<h3>NTP Health Status</h3>" -As Table
        }
        else {
            $allNtpObject | Sort-Object Component, Resource 
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-NtpHealth

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
        $allvsanClusterObject = New-Object System.Collections.ArrayList # Define the object for all data
        $vsanClusterData = $targetContent.VSAN.'Cluster vSAN Status' # Extract specific data from all data read in from the JSON file
        foreach ($element in $vsanClusterData.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue (($element.area -Split (" : "))[1].Trim() -Split (" - "))[0]
            $elementObject | Add-Member -notepropertyname 'Cluster' -notepropertyvalue ($element.area -Split ("Cluster : "))[-1]
            $elementObject | Add-Member -notepropertyname 'Check' -notepropertyvalue $element.title
            $elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $allvsanClusterObject += $elementObject
                }
            }
            else {
                $allvsanClusterObject += $elementObject
            }
        }
        $clusterDiskData = $targetContent.VSAN.'Cluster Disk Status' # Extract specific data from all data read in from the JSON file
        foreach ($element in $clusterDiskData.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue (($element.area -Split (" : "))[1].Trim() -Split (" - "))[0]
            $elementObject | Add-Member -notepropertyname 'Cluster' -notepropertyvalue ($element.area -Split ("Cluster : "))[-1]
            $elementObject | Add-Member -notepropertyname 'Check' -notepropertyvalue $element.title
            $elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $allvsanClusterObject += $elementObject
                }
            }
            else {
                $allvsanClusterObject += $elementObject
            }
            $allvsanClusterObject += $elementObject
        }
        $compressionData = $targetContent.VSAN.'Cluster Data Compression Status' # Extract specific data from all data read in from the JSON file
        foreach ($element in $compressionData.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue (($element.area -Split (" : "))[1].Trim() -Split (" - "))[0]
            $elementObject | Add-Member -notepropertyname 'Cluster' -notepropertyvalue ($element.area -Split ("Cluster : "))[-1]
            $elementObject | Add-Member -notepropertyname 'Check' -notepropertyvalue $element.title
            $elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $allvsanClusterObject += $elementObject
                }
            }
            else {
                $allvsanClusterObject += $elementObject
            }
        }
        $encryptionData = $targetContent.VSAN.'Cluster Data Encryption Status' # Extract specific data from all data read in from the JSON file
        foreach ($element in $encryptionData.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue (($element.area -Split (" : "))[1].Trim() -Split (" - "))[0]
            $elementObject | Add-Member -notepropertyname 'Check' -notepropertyvalue $element.title
            $elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $allvsanClusterObject += $elementObject
                }
            }
            else {
                $allvsanClusterObject += $elementObject
            }
        }
        $dedupeData = $targetContent.VSAN.'Cluster Data Deduplication Status' # Extract specific data from all data read in from the JSON file
        foreach ($element in $dedupeData.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue (($element.area -Split (" : "))[1].Trim() -Split (" - "))[0]
            $elementObject | Add-Member -notepropertyname 'Check' -notepropertyvalue $element.title
            $elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $allvsanClusterObject += $elementObject
                }
            }
            else {
                $allvsanClusterObject += $elementObject
            }
        $stretchedClusterData = $targetContent.VSAN.'Stretched Cluster Status' # Extract specific data from all data read in from the JSON file
        foreach ($element in $stretchedClusterData.PsObject.Properties.Value) {
            $elementObject = New-Object -TypeName psobject
            $elementObject | Add-Member -notepropertyname 'Resource' -notepropertyvalue (($element.area -Split (" : "))[1].Trim() -Split (" - "))[0]
            $elementObject | Add-Member -notepropertyname 'Check' -notepropertyvalue $element.title
            $elementObject | Add-Member -notepropertyname 'Status' -notepropertyvalue $element.status.ToUpper()
            $elementObject | Add-Member -notepropertyname 'Alert' -notepropertyvalue $element.alert
            $elementObject | Add-Member -notepropertyname 'Message' -notepropertyvalue $element.message
            if ($PsBoundParameters.ContainsKey("failureOnly")) {
                if (($element.status -eq "FAILED")) {
                    $allvsanClusterObject += $elementObject
                }
            }
            else {
                $allvsanClusterObject += $elementObject
            }
        }
        if ($PsBoundParameters.ContainsKey("html")) { 
            $allvsanClusterObject | Sort-Object Resource, Cluster, 'Check' | ConvertTo-Html -Fragment -PreContent "<h3>VSAN Cluster Health Status</h3>" -As Table
        }
        else {
            $allvsanClusterObject | Sort-Object Resource, Cluster, 'Check' 
        }
    }
    Catch {
        Debug-CatchWriter -object $_
    }
}
Export-ModuleMember -Function Publish-VsanHealth

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

Function Convert-TextToHtml {
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$sourceFile,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$label
    )

    Get-Content $sourceFile | ConvertTo-HTML -Property @{Label=$label;Expression={$_}} -Fragment
}
Export-ModuleMember -Function Convert-TextToHtml

Function PercentCalc {
    Param (
        [Parameter (Mandatory = $true)] [Int]$InputNum1,
        [Parameter (Mandatory = $true)] [Int]$InputNum2)
        $InputNum1 / $InputNum2*100
}
