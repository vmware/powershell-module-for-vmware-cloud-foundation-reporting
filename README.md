# `VMware.CloudFoundation.Reporting`

A PowerShell module for VMware Cloud Foundation reporting.

## Overview

`VMware.CloudFoundation.Reporting` is a PowerShell module that has been written to support the ability to provide insight to the operational state of VMware Cloud Foundation through the use of PowerShell cmdlets. These cmdlets provide quick access to information from the PowerShell console as well as the ability to publish pre-defined HTML reports.

The PowerShell Module provides customers the ability to generate the following reports:

- [Overview Report](#generating-system-overview-report-tasks)
- [Health Report](#generating-health-report-tasks)
- [Alert Report](#generating-system-alert-report-tasks)
- [Password Policy Report](#generating-password-policy-report-tasks)
- [Configuration Report](#generating-configuration-report-tasks)
- [Upgrade Precheck Report](#generating-upgrade-precheck-report-tasks)

Example:

![Screenshot](screenshot.png)

>**Note**: Reports default to a light-mode theme. If you prefer a dark-mode theme, you can use the `-dark` parameter with each `Invoke-Vcf*Report` cmdlets.

## Requirements

### Supported Platforms

- VMware Cloud Foundation 4.2.1 and later

### Operating System

- Microsoft Windows Server 2019 or later.
- Microsoft Windows 10 or later.

### PowerShell

- Microsoft Windows PowerShell 5.1

### Browser

- Microsoft Edge
- Google Chrome
- Mozilla Firefox

## Installing the Module

Verify that your system has Microsoft Windows PowerShell 5.1 installed. See [Microsoft Windows PowerShell][microsoft-windows-powershell].

Install the supporting PowerShell modules from the PowerShell Gallery by running the following commands:

```powershell
Install-Module -Name VMware.PowerCLI -MinimumVersion 12.4.1
Install-Module -Name VMware.vSphere.SsoAdmin -MinimumVersion 1.3.7
Install-Module -Name PowerVCF -MinimumVersion 2.1.7
Install-Module -Name PowerValidatedSolutions -MinimumVersion 1.6.0
Install-Module -Name VMware.CloudFoundation.Reporting -RequiredVersion 0.0.3
```

If you experience an error downloading the module from the PSGallery you may need to run the following command in the Windows PowerShell console to enable TLS 1.2.

```powershell
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
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
Get-Help -Name Invoke-VcfHealthReport
```

```powershell
Get-Help -Name Invoke-VcfHealthReport -Examples
```

## Getting Started

### Generating System Overview Report Tasks

The `Invoke-VcfOverviewReport` cmdlet generates a system overview report. This report contains high-level information about the VMware Cloud Foundation system. This report may be used to provide a quick system overview of the system to your VMware representative.

#### Generate a System Overview Report for a VMware Cloud Foundation Instance

1. Start Windows PowerShell.

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a system overview report for SDDC Manager instance and run the commands in the PowerShell console.

    ```powershell
    $sddcManagerFqdn = "sfo-vcf01.sfo.rainpole.io"
    $sddcManagerUser = "admin@local"
    $sddcManagerPass = "VMw@re1!VMw@re1!"

    $sddcManagerRootPass = "VMw@re1!"
    $reportPath = "F:\Reporting"
    ```

3. Perform the configuration by running the command in the PowerShell console.

    ```powershell
    Invoke-VcfOverviewReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -reportPath $reportPath
    ```

    If you prefer to anonymize the data, you can use the `-anonymized` parameter.

    ```powershell
    Invoke-VcfOverviewReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -reportPath $reportPath -anonymized
    ```

4. Review the generated HTML report.

### Generating Health Report Tasks

The `Invoke-VcfHealthReport` cmdlet generates a health report. This report combines the SoS Utility health checks with additional health checks not presently available in the SoS Utility for previous VMware Cloud Foundation releases. The report contains detailed information about the health of the VMware Cloud Foundation system and its components.

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

The `Invoke-VcfSystemAlertReport` cmdlet generates a system alert report. This report collects information about the system alerts that are currently active in the VMware Cloud Foundation system for the platform components. This report reduces the need to login to multiple product interfaces to collect information about the system alerts.

#### Generate a System Alert Report for a VMware Cloud Foundation Instance (Display Only Issues)

1. Start Windows PowerShell.

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a system alert report for SDDC Manager instance and run the commands in the PowerShell console.

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

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a system alert report for SDDC Manager instance and run the commands in the PowerShell console.

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

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a system alert report for SDDC Manager instance and run the commands in the PowerShell console.

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

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a system alert report for SDDC Manager instance and run the commands in the PowerShell console.

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

### Generating Password Policy Report Tasks

The `Invoke-VcfPasswordPolicyReport` cmdlet generates a password policy report. This report collects information about the password policy settings in a VMware Cloud Foundation system for the platform components. This report reduces the need to login to multiple product interfaces and endpoints to collect information about the password policy.

#### Generate a Password Policy Report for a VMware Cloud Foundation Instance

1. Start Windows PowerShell.

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a password policy report for SDDC Manager instance and run the commands in the PowerShell console.

    ```powershell
    $sddcManagerFqdn = "sfo-vcf01.sfo.rainpole.io"
    $sddcManagerUser = "admin@local"
    $sddcManagerPass = "VMw@re1!VMw@re1!"

    $sddcManagerRootPass = "VMw@re1!"
    $reportPath = "F:\Reporting"
    ```

3. Perform the configuration by running the command in the PowerShell console.

    ```powershell
    Invoke-VcfPasswordPolicy -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -reportPath $reportPath -allDomains
    ```

4. Review the generated HTML report.

#### Generate a Password Policy Report for a Workload Domain

1. Start Windows PowerShell.

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a password policy report for SDDC Manager instance and run the commands in the PowerShell console.

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
    Invoke-VcfPasswordPolicy -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -reportPath $reportPath -workloadDomain $workloadDomain
    ```

4. Review the generated HTML report.

### Generating Configuration Report Tasks

The `Invoke-VcfConfigurationReport` cmdlet generates a configuration report. This report collects information about the configuration settings in a VMware Cloud Foundation system for the platform components. This report reduces the need to login to multiple product interfaces and endpoints to collect information about the configuration.

#### Generate a Configuration Report for a VMware Cloud Foundation Instance

1. Start Windows PowerShell.

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a configuration report for SDDC Manager instance and run the commands in the PowerShell console.

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

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a configuration report for SDDC Manager instance and run the commands in the PowerShell console.

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

The upgrade precheck report, initiates an upgrade precheck of a workload domain using the REST API and presents the results in an HTML report. This allows you to start the precheck from the PowerShell console.

#### Perform an Upgrade Precheck for a Workload Domain

1. Start Windows PowerShell.

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate an upgrade precheck report for SDDC Manager instance and run the commands in the PowerShell console.

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

## Support

This module is not supported by VMware Support.

## References

- [VMware PowerCLI](https://developer.vmware.com/powercli)
- [PowerVCF](https://github.com/powervcf/powervcf/)
- [PowerValidatedSolutions](https://github.com/vmware-samples/power-validated-solutions-for-cloud-foundation)

## License

Copyright 2022 VMware, Inc.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

[//]: Links

[microsoft-windows-powershell]: https://docs.microsoft.com/en-us/powershell/
