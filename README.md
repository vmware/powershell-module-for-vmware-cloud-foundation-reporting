# `VMware.CloudFoundation.Reporting`

A PowerShell module for VMware Cloud Foundation reporting.

## Overview

`VMware.CloudFoundation.Reporting` is a PowerShell module that has been written to support the ability to provide insight to the operational state of VMware Cloud Foundation through the use of PowerShell cmdlets. These cmdlets provide quick access to information from the PowerShell console as well as the ability to publish the following HTML reports.

- [Health Reports](#generating-health-report-tasks)
- [Alert Reports](#generating-system-alert-report-tasks)
- [Configuration Reports](#generating-configuration-report-tasks)
- [Upgrade Precheck Reports](#generating-upgrade-precheck-report-tasks)

Example:

![Screenshot](screenshot.png)

## Installing the Module

Verify that your system has Microsoft Windows PowerShell 5.1 installed. See [Microsoft Windows PowerShell][microsoft-windows-powershell].

Install the supporting PowerShell modules from the PowerShell Gallery by running the following commands:

```powershell
Install-Module -Name VMware.PowerCLI -MinimumVersion 12.4.1
Install-Module -Name VMware.vSphere.SsoAdmin -MinimumVersion 1.3.7
Install-Module -Name PowerVCF -MinimumVersion 2.1.7
Install-Module -Name PowerValidatedSolutions -MinimumVersion 1.5.0
Install-Module -Name VMware.CloudFoundation.Reporting -MinimumVersion 1.0.0
```

To verify the modules are installed, run the following command in the PowerShell console.

```powershell
Get-InstalledModule
```

Once installed, any new cmdlet associated with `VMware.CloudFoundation.Reporting` and it's supporting PowerShell modules will be available for use.

To view the cmdlets for available in the module, run the following command in the PowerShell console.

```powershell
Get-Command -Module VMware.CloudFoundation.Reporting
```

To view the help for any cmdlet, run the `Get-Help` command in the PowerShell console.

For example:

```powershell
Get-Help -Module Invoke-VcfHealthReport
```

```powershell
Get-Help -Module Invoke-VcfHealthReport -Examples
```

## Getting Started

### Generating Health Report Tasks

#### Generate a Health Report for a VMware Cloud Foundation Instance (Display Only Issues)

1. Start Windows PowerShell.

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a health report for SDDC Manager instance and run the commands in the PowerShell console.

    ```powershell
    $sddcManagerFqdn = "sfo-vcf01.sfo.rainpole.io"
    $sddcManagerUser = "admin@local"
    $sddcManagerPass = "VMw@re1!VMw@re1!"

    $sddcManagerRootPass = "VMw@re1!"
    $reportPath = "F:\Reporting"
    ```

3. Perform the configuration by running the command in the PowerShell console.

    ```powershell
    Invoke-VcfHealthReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -sddcManagerRootPass $sddcManagerRootPass -reportPath $reportPath -allDomains -failureOnly
    ```

4. Review the generated HTML report and perform remediation of any identified issues.

#### Generate a Health Report for a Workload Domain (Display Only Issues)

1. Start Windows PowerShell.

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a health report for SDDC Manager instance and run the commands in the PowerShell console.

    ```powershell
    $sddcManagerFqdn = "sfo-vcf01.sfo.rainpole.io"
    $sddcManagerUser = "admin@local"
    $sddcManagerPass = "VMw@re1!VMw@re1!"

    $sddcManagerRootPass = "VMw@re1!"
    $workloadDomain = "sfo-m01"
    $reportPath = "F:\Reporting"
    ```

3. Perform the configuration by running the command in the PowerShell console.

    ```powershell
    Invoke-VcfHealthReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -sddcManagerRootPass $sddcManagerRootPass -reportPath $reportPath -workloadDomain $workloadDomain -failureOnly
    ```

4. Review the generated HTML report and perform remediation of any identified issues.

### Generate a Health Report for a VMware Cloud Foundation Instance

1. Start Windows PowerShell.

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a health report for SDDC Manager instance and run the commands in the PowerShell console.

    ```powershell
    $sddcManagerFqdn = "sfo-vcf01.sfo.rainpole.io"
    $sddcManagerUser = "admin@local"
    $sddcManagerPass = "VMw@re1!VMw@re1!"

    $sddcManagerRootPass = "VMw@re1!"
    $reportPath = "F:\Reporting"
    ```

3. Perform the configuration by running the command in the PowerShell console.

    ```powershell
    Invoke-VcfHealthReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -sddcManagerRootPass $sddcManagerRootPass -reportPath $reportPath -allDomains
    ```

4. Review the generated HTML report and perform remediation of any identified issues.

### Generate a Health Report for a Workload Domain

1. Start Windows PowerShell.

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a health report for SDDC Manager instance and run the commands in the PowerShell console.

    ```powershell
    $sddcManagerFqdn = "sfo-vcf01.sfo.rainpole.io"
    $sddcManagerUser = "admin@local"
    $sddcManagerPass = "VMw@re1!VMw@re1!"

    $sddcManagerRootPass = "VMw@re1!"
    $workloadDomain = "sfo-m01"
    $reportPath = "F:\Reporting"
    ```

3. Perform the configuration by running the command in the PowerShell console.

    ```powershell
    Invoke-VcfHealthReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -sddcManagerRootPass $sddcManagerRootPass -reportPath $reportPath -workloadDomain $workloadDomain
    ```

4. Review the generated HTML report and perform remediation of any identified issues.

### Generating System Alert Report Tasks

#### Generate a System Alert Report for a VMware Cloud Foundation Instance (Display Only Issues)

1. Start Windows PowerShell.

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a health report for SDDC Manager instance and run the commands in the PowerShell console.

    ```powershell
    $sddcManagerFqdn = "sfo-vcf01.sfo.rainpole.io"
    $sddcManagerUser = "admin@local"
    $sddcManagerPass = "VMw@re1!VMw@re1!"

    $reportPath = "F:\Reporting"
    ```

3. Perform the configuration by running the command in the PowerShell console.

    ```powershell
    Invoke-VcfAlertReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -reportPath $reportPath -allDomains -failureOnly
    ```

4. Review the generated HTML report and perform remediation of any identified issues.

#### Generate a System Alert Report for a Workload Domain (Display Only Issues)

1. Start Windows PowerShell.

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a health report for SDDC Manager instance and run the commands in the PowerShell console.

    ```powershell
    $sddcManagerFqdn = "sfo-vcf01.sfo.rainpole.io"
    $sddcManagerUser = "admin@local"
    $sddcManagerPass = "VMw@re1!VMw@re1!"

    $workloadDomain = "sfo-m01"
    $reportPath = "F:\Reporting"
    ```

3. Perform the configuration by running the command in the PowerShell console.

    ```powershell
    Invoke-VcfAlertReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -reportPath $reportPath -workloadDomain $workloadDomain -failureOnly
    ```

4. Review the generated HTML report and perform remediation of any identified issues.

#### Generate a System Alert Report for a VMware Cloud Foundation Instance

1. Start Windows PowerShell.

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a health report for SDDC Manager instance and run the commands in the PowerShell console.

    ```powershell
    $sddcManagerFqdn = "sfo-vcf01.sfo.rainpole.io"
    $sddcManagerUser = "admin@local"
    $sddcManagerPass = "VMw@re1!VMw@re1!"

    $reportPath = "F:\Reporting"
    ```

3. Perform the configuration by running the command in the PowerShell console.

    ```powershell
    Invoke-VcfAlertReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -reportPath $reportPath -allDomains
    ```

4. Review the generated HTML report and perform remediation of any identified issues.

#### Generate a System Alert Report for a Workload Domain

1. Start Windows PowerShell.

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a health report for SDDC Manager instance and run the commands in the PowerShell console.

    ```powershell
    $sddcManagerFqdn = "sfo-vcf01.sfo.rainpole.io"
    $sddcManagerUser = "admin@local"
    $sddcManagerPass = "VMw@re1!VMw@re1!"

    $workloadDomain = "sfo-m01"
    $reportPath = "F:\Reporting"
    ```

3. Perform the configuration by running the command in the PowerShell console.

    ```powershell
    Invoke-VcfAlertReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -reportPath $reportPath -workloadDomain $workloadDomain
    ```

4. Review the generated HTML report and perform remediation of any identified issues.

### Generating Configuration Report Tasks

#### Generate a Configuration Report for a VMware Cloud Foundation Instance

1. Start Windows PowerShell.

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a health report for SDDC Manager instance and run the commands in the PowerShell console.

    ```powershell
    $sddcManagerFqdn = "sfo-vcf01.sfo.rainpole.io"
    $sddcManagerUser = "admin@local"
    $sddcManagerPass = "VMw@re1!VMw@re1!"

    $reportPath = "F:\Reporting"
    ```

3. Perform the configuration by running the command in the PowerShell console.

    ```powershell
    Invoke-VcfConfigReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -reportPath $reportPath -allDomains
    ```

4. Review the generated HTML report.

#### Generate a Configuration Report for a Workload Domain

1. Start Windows PowerShell.

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a health report for SDDC Manager instance and run the commands in the PowerShell console.

    ```powershell
    $sddcManagerFqdn = "sfo-vcf01.sfo.rainpole.io"
    $sddcManagerUser = "admin@local"
    $sddcManagerPass = "VMw@re1!VMw@re1!"

    $workloadDomain = "sfo-m01"
    $reportPath = "F:\Reporting"
    ```

3. Perform the configuration by running the command in the PowerShell console.

    ```powershell
    Invoke-VcfConfigReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -reportPath $reportPath -workloadDomain $workloadDomain
    ```

4. Review the generated HTML report.

### Generating Upgrade Precheck Report Tasks

#### Perform an Upgrade Precheck for a Workload Domain

1. Start Windows PowerShell.

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a health report for SDDC Manager instance and run the commands in the PowerShell console.

    ```powershell
    $sddcManagerFqdn = "sfo-vcf01.sfo.rainpole.io"
    $sddcManagerUser = "admin@local"
    $sddcManagerPass = "VMw@re1!VMw@re1!"

    $workloadDomain = "sfo-m01"
    $reportPath = "F:\Reporting"
    ```

3. Perform the configuration by running the command in the PowerShell console.

    ```powershell
    Invoke-VcfUpgradePrecheck -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -reportPath $reportPath -workloadDomain $workloadDomain
    ```

4. Review the generated HTML report.

## License

Copyright 2022 VMware, Inc.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

[//]: Links

[microsoft-windows-powershell]: https://docs.microsoft.com/en-us/powershell/
