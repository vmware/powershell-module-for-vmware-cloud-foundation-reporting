# CHANGELOG

## [v2.0.0](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/releases/tag/v2.0.0)

> Release Date: Unreleased

Enhancement:
- Updates `Publish-CertificateHealth` with thresholds based on certificate expiration. [GH-107](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/107)
- Updates `Publish-CertificateHealth` to include an "Expires In (Days)" column. [GH-107](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/107)
- Updates `Publish-CertificateHealth` to include ESXi host certificates. [GH-107](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/107)
- Updates `Publish-PasswordHealth` to include an "Expires In (Days)" column. [GH-111](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/111)

Refactor:
- Updates `Request-SoSHealthJson` to use the API to retrieve the SoS Health Summary JSON results. [GH-102](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/102)
- Updates `Publish-PasswordHealth` to return the results from the SoS Health Summary JSON data. [GH-111](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/111)
- Updates `Invoke-VcfHealthReport` to use the `Publish-PasswordHealth` cmdlet. [GH-111](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/111)
- Removes `Publish-LocalUserExpiry` in favor of the `Publish-PasswordHealth` cmdlet. [GH-111](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/111)

## [v1.1.0](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/releases/tag/v1.1.0)

> Release Date: 2023-02-28

Bugfix:
- Updates `Request-VcenterBackupStatus` backup message to remove the SDDC Manager FQDN when backups are located on the SDDC Manager. Required for Heatlh Monitoring and Reporting solution alerts. [GH-95](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/95)
- Updates `Publish-vCenerHealth` to correctly link and display the vCenter Server Ring Topology Health from SoS. [GH-94](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/94)
- Resolves an issue with the display name of the vRealize Log Insight product name in the `Request-VrealizeOverview`due to an upstream error in the `.SYNOPSIS` of `Get-VCFvRLI` in `PowerVCF`. [GH-86](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/86)
- Updates `Test-VcfReportingPrereq` to return results when run on Photon OS. [GH-82](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/82)

Enhancement:
- Updates `Publish-*` cmdlets to support JSON generation. Required for Heatlh Monitoring and Reporting solution. [GH-79](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/79)
    - `Publish-BackupStatus`
    - `Publish-NsxtTransportNodeStatus`
    - `Publish-NsxtTier0BgpStatus`
    - `Publish-SnapshotStatus`
    - `Publish-LocalUserExpiry`
    - `Publish-StorageCapacityHealth`
- Adds `Publish-NsxtHealthNonSOS` and `Publish-ComponentConnectivityHealthNonSOS` cmdlets. Required for Heatlh Monitoring and Reporting solution. [GH-79](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/79)
- Updates in `Publish-*` cmdlets that support JSON generation to specify encoding needed for Python to read it the content. Required for Heatlh Monitoring and Reporting solution alerts. [GH-93](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/93)
- Adds CPU Cores per Socket to the ESXi Host Overview on the overview report. [GH-85](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/85)
- Adds an option to `Request-ESXiOverview` to report on the VCF+ subscription cores and export the results to CSV. [GH-87](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/87)

Documenation:
- Updates `README.md` to remove the **Known Issues** section and adds references to the GitHub issue tracker for support. [GH-88](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/88)
- Updates `README.md` documentation to include support for DellEMC VxRAIL. [GH-98](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/98)

Chore:
- Removes the password policy functions that were moved to `PowerValidatedSolutions` v2.0.0. [GH-100](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/100)
- Updates `PowerValidatedSolutions` from v2.0.0 to v2.0.1. [GH-99](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/99)

## [v1.0.6](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/releases/tag/v1.0.6)

> Release Date: 2023-01-31

Bugfix:

- Updates `Request0VcenterOverview` to use the PowerVCF cmdlets to return the workload domain's cluster and host counts from the SDDC Manager inventory versus directly from the vSphere inventory. This will ensure that the host count does not include any HCX nodes. [GH-65](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/65)
- Updates `Publish-NsxtCombinedHealth` to use `$json` when calling `Publish-NsxtHealth`. [GH-59](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/59)
- Updates `Request-NsxtEdgeUserExpiry` to resolve error if an NSX Edge `root` password is different from NSX Manager `root` password. [GH-75](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/75)

Enhancement:

- Updated `Invoke-VcfPasswordPolicy` cmdlet with new password expiration, complexity and account lockout details. [GH-53](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/53)

Documenation:

- Adds a section for **Updating the Module** to the `README.md` documentation. [GH-57](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/57)

Chore:

- Updates `PowerValidatedSolutions` from v1.10.0 to v2.0.0. [GH-35](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/35)

Refactor:

- Refactors `Publish-StorageCapacityHealth` for code efficiency. [GH-64](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/64)
- Refactors `Invoke-VcfPasswordPolicy` for code efficiency. [GH-63](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/63)
- Refactors `Invoke-VcfConfigReport` for code efficiency. [GH-62](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/62)
- Refactors `Invoke-VcfAlertReport` for code efficiency. [GH-61](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/61)
- Refactors `Invoke-VcfHealthReport` for code efficiency. [GH-60](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/60)
- Transfers `Publish-EsxiPasswordPolicy` to `PowerValidatedSolutions` module. [GH-55](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/55)

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
