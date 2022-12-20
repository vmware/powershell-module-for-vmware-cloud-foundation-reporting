# CHANGELOG

## [v1.0.6]

Enhancement:

- Updated `Invoke-VcfPasswordPolicy` cmdlet with new password expiration, complexity and account lockout details.

## [v1.0.5](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/releases/tag/v1.0.5)

> Release Date: 2022-12-20

Bugfix:

- Updates `Request-NsxtVidmStatus` and `Request-NsxtComputeManagerStatus` functions to resolve an issue supporting workload domains with shared NSX Local Managers on the health report. [GH-25](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/25)
- Updates `Request-NsxtComputeManagerStatus` function to resolve an issue with supporting workload domains with shared NSX Local Managers on the health report; a false negative for "rogue" compute managers (vCenter Server instances) registered in NSX Local Managers. [GH-42](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/42)
- Updates `Publish-CertificateHealth` function to resolve an issue accurately dosplaying the certificate health on the health report. [GH-43](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/43)
- Updates `Request-SddcManagerFreePool` function to resolve an issue returning the free pool health for the heatlh report if the ESXi host license is expired. [GH-32](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/32)
- Updates `Test-VcfReportingPrereq` to display an error on the PowerShell console if the version of a PowerShell module dependency does not meet the minimum requirements. [GH-35](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/35)

Enhancement:

- Adds support for including the number of ESXi hosts per cluster in the system overview Report. [GH-46](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/46)
- Adds `Request-EsxiOverview` and updates `Publish-VcfSystemOverview` functions to return the high-level status of each ESXi host on the system overview report. [GH-33](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/33)
- Adds support for vRealize Log Insight, vRealize Operations, vRealize Automation, and Workspace ONE Access in the `Request-LocalUserExpiry` function. [GH-32](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/31)
- Removes the `Test-VcfReportingPrereq` from the `Invoke-*` function which reduces report initialization time. [GH-24](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/24)
- Updates `Test-VcfReportingPrereq` to display the version of an installed PowerShell module dependency. [GH-27](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/27)

Refactor:

- Replaces local `getNsxtServerDetail` function with `Get-NsxtServerDetail` function exported from `PowerValidatedSolutions`. [GH-35](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/35)

Chore:

- Updates `PowerValidatedSolutions` from v1.7.0 to v1.10.0. [GH-35](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/35)
- Updates `VMware.PowerCLI` from v12.4.1 to v12.7.0. [GH-35](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/35)
- Updates `VMware.vSphere.SsoAdmin` from v1.3.7 to v1.3.8. [GH-35](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/35)

## [v1.0.4](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/releases/tag/v1.0.4)

> Release Date: 2022-10-10

Initial availability of the PowerShell module for VMware Cloud Foundation Reporting.
