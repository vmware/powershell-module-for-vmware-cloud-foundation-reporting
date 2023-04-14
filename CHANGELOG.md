# CHANGELOG

## [v2.0.0](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/releases/tag/v2.0.0)

> Release Date: Unreleased

Enhancement:

- Updated `Publish-CertificateHealth` with thresholds based on certificate expiration. [GH-107](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/107)
- Updated `Publish-CertificateHealth` to include an "Expires In (Days)" column. [GH-107](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/107)
- Updated `Publish-CertificateHealth` to include ESXi host certificates. [GH-107](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/107)
- Updated `Publish-PasswordHealth` to include an "Expires In (Days)" column. [GH-111](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/111)
- Added `Publish-VersionHealth` to return the version health from the SoS Health Summary JSON data.
- Updated `Invoke-VcfHealthReport` to include the version health using the `Publish-VersionHealth` cmdlet.
- Added `Show-ReportingOutput` cmdlet to format output to the console when `PowerVCF` is not installed. [GH-121](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/121)
- Updated `Publish-VsanHealth` to include the results for capacity utilization and the active resysc of objects.

Refactor:

- **Breaking**: Updated `Invoke-VcfReportingPrereq` to:
    - Use `-sddcManagerFqdn`, `sddcManagerUser`, and `sddcManagerPass` parameters to check the SDDC Manager version. [GH-117](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/117)
    - Use `Write-LogMessage` to apply colors to the output and log the output to a file using the `-logPath` parameter. [GH-117](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/117)
- **Breaking**: Updated `Invoke-VcfHealthReport` to use `-sddcManagerLocalUser` and `-sddcManagerLocalPass` parameters instead of `-SddcManagerRootPass`. Examples use the local `vcf` user account for the SDDC Manager virtual appliance. [GH-113](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/113)
- **Breaking**: Updated `Publish-StorageCapacityHealth` to use `-localUser` and `-localPass` parameters instead of `-rootPass`. Examples use the local `vcf` user account for the SDDC Manager virtual appliance. [GH-113](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/113)
- **Breaking**: Updated `Request-SddcManagerStorageHealth` to use `-localUser` and `-localPass` parameters instead of `-rootPass`. Examples use the local `vcf` user account for the SDDC Manager virtual appliance. [GH-113](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/113)
- **Breaking**: Removed `Invoke-VcfPasswordPolicy` and supporting content. Please use the [`VMware.CloudFoundation.PasswordManagement`](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-password-management) module. [GH-118](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/118)
- Updated `Request-SoSHealthJson` to use the API to retrieve the SoS Health Summary JSON results. [GH-102](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/102)
- Updated `Publish-PasswordHealth` to return the results from the SoS Health Summary JSON data. [GH-111](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/111)
- Updated `Invoke-VcfHealthReport` to use the `Publish-PasswordHealth` cmdlet. [GH-111](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/111)
- Removed `Publish-LocalUserExpiry` and supporting functions in favor of the `Publish-PasswordHealth` cmdlet. [GH-111](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/111)
- Removed `Request-LocalUserExpiry` which supported the `Publish-LocalUserExpiry` cmdlet. Results are now returned from the SoS Health Summary JSON data. [GH-120](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/120)
- Removed `Request-SddcManagerUserExpiry` which supported the `Publish-LocalUserExpiry` cmdlet. [GH-120](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/120)
- Removed `Request-vCenterUserExpiry` which supported the `Publish-LocalUserExpiry` cmdlet. [GH-120](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/120)
- Removed `Request-NsxtManagerUserExpiry` which supported the `Publish-LocalUserExpiry` cmdlet. [GH-120](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/120)
- Removed `Request-NsxtEdgeUserExpiry` which supported the `Publish-LocalUserExpiry` cmdlet. [GH-120](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/120)
- Removed `Request-Request-vRslcmUserExpiry` which supported the `Publish-LocalUserExpiry` cmdlet. [GH-120](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/120)

Chore:

- Updated `PowerValidatedSolutions` from v2.0.1 to v2.2.0. [GH-117](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/117)
- Updated `VMware.PowerCLI` from v12.7.0 to v13.0.0. [GH-117](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/117)
- Updated `VMware.vSphere.SsoAdmin` from v1.3.8 to v1.3.9. [GH-117](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/117)

## [v1.1.0](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/releases/tag/v1.1.0)

> Release Date: 2023-02-28

Bugfix:

- Updated `Request-VcenterBackupStatus` backup message to remove the SDDC Manager FQDN when backups are located on the SDDC Manager. Required for Heatlh Monitoring and Reporting solution alerts. [GH-95](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/95)
- Updated `Publish-vCenterHealth` to correctly link and display the vCenter Server Ring Topology Health from SoS. [GH-94](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/94)
- Resolves an issue with the display name of the vRealize Log Insight product name in the `Request-VrealizeOverview`due to an upstream error in the `.SYNOPSIS` of `Get-VCFvRLI` in `PowerVCF`. [GH-86](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/86)
- Updated `Test-VcfReportingPrereq` to return results when run on Photon OS. [GH-82](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/82)

Enhancement:

- Updated `Publish-*` cmdlets to support JSON generation. Required for Heatlh Monitoring and Reporting solution. [GH-79](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/79)
    - `Publish-BackupStatus`
    - `Publish-NsxtTransportNodeStatus`
    - `Publish-NsxtTier0BgpStatus`
    - `Publish-SnapshotStatus`
    - `Publish-LocalUserExpiry`
    - `Publish-StorageCapacityHealth`
- Added `Publish-NsxtHealthNonSOS` and `Publish-ComponentConnectivityHealthNonSOS` cmdlets. Required for Heatlh Monitoring and Reporting solution. [GH-79](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/79)
- Updated in `Publish-*` cmdlets that support JSON generation to specify encoding needed for Python to read it the content. Required for Heatlh Monitoring and Reporting solution alerts. [GH-93](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/93)
- Added CPU Cores per Socket to the ESXi Host Overview on the overview report. [GH-85](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/85)
- Added an option to `Request-ESXiOverview` to report on the VCF+ subscription cores and export the results to CSV. [GH-87](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/87)

Documenation:

- Updated `README.md` to remove the **Known Issues** section and adds references to the GitHub issue tracker for support. [GH-88](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/88)
- Updated `README.md` documentation to include support for DellEMC VxRAIL. [GH-98](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/98)

Chore:

- Removed the password policy functions that were moved to `PowerValidatedSolutions` v2.0.0. [GH-100](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/100)
- Updated `PowerValidatedSolutions` from v2.0.0 to v2.0.1. [GH-99](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/99)

## [v1.0.6](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/releases/tag/v1.0.6)

> Release Date: 2023-01-31

Bugfix:

- Updated `Request0VcenterOverview` to use the PowerVCF cmdlets to return the workload domain's cluster and host counts from the SDDC Manager inventory versus directly from the vSphere inventory. This will ensure that the host count does not include any HCX nodes. [GH-65](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/65)
- Updated `Publish-NsxtCombinedHealth` to use `$json` when calling `Publish-NsxtHealth`. [GH-59](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/59)
- Updated `Request-NsxtEdgeUserExpiry` to resolve error if an NSX Edge `root` password is different from NSX Manager `root` password. [GH-75](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/75)

Enhancement:

- Updated `Invoke-VcfPasswordPolicy` cmdlet with new password expiration, complexity and account lockout details. [GH-53](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/53)

Documenation:

- Added a section for **Updating the Module** to the `README.md` documentation. [GH-57](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/57)

Chore:

- Updated `PowerValidatedSolutions` from v1.10.0 to v2.0.0. [GH-35](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/35)

Refactor:

- Refactored `Publish-StorageCapacityHealth` for code efficiency. [GH-64](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/64)
- Refactored `Invoke-VcfPasswordPolicy` for code efficiency. [GH-63](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/63)
- Refactored `Invoke-VcfConfigReport` for code efficiency. [GH-62](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/62)
- Refactored `Invoke-VcfAlertReport` for code efficiency. [GH-61](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/61)
- Refactored `Invoke-VcfHealthReport` for code efficiency. [GH-60](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/60)
- Transfered `Publish-EsxiPasswordPolicy` to `PowerValidatedSolutions` module. [GH-55](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/55)

## [v1.0.5](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/releases/tag/v1.0.5)

> Release Date: 2022-12-20

Bugfix:

- Updated `Request-NsxtVidmStatus` and `Request-NsxtComputeManagerStatus` functions to resolve an issue supporting workload domains with shared NSX Local Managers on the health report. [GH-25](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/25)
- Updated `Request-NsxtComputeManagerStatus` function to resolve an issue with supporting workload domains with shared NSX Local Managers on the health report; a false negative for "rogue" compute managers (vCenter Server instances) registered in NSX Local Managers. [GH-42](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/42)
- Updated `Publish-CertificateHealth` function to resolve an issue accurately dosplaying the certificate health on the health report. [GH-43](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/43)
- Updated `Request-SddcManagerFreePool` function to resolve an issue returning the free pool health for the heatlh report if the ESXi host license is expired. [GH-32](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/32)
- Updated `Test-VcfReportingPrereq` to display an error on the PowerShell console if the version of a PowerShell module dependency does not meet the minimum requirements. [GH-35](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/35)

Enhancement:

- Added support for including the number of ESXi hosts per cluster in the system overview Report. [GH-46](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/46)
- Added `Request-EsxiOverview` and updates `Publish-VcfSystemOverview` functions to return the high-level status of each ESXi host on the system overview report. [GH-33](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/33)
- Added support for vRealize Log Insight, vRealize Operations, vRealize Automation, and Workspace ONE Access in the `Request-LocalUserExpiry` function. [GH-32](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/31)
- Removed the `Test-VcfReportingPrereq` from the `Invoke-*` function which reduces report initialization time. [GH-24](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/24)
- Updated `Test-VcfReportingPrereq` to display the version of an installed PowerShell module dependency. [GH-27](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/27)

Refactor:

- Replaces local `getNsxtServerDetail` function with `Get-NsxtServerDetail` function exported from `PowerValidatedSolutions`. [GH-35](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/35)

Chore:

- Updated `PowerValidatedSolutions` from v1.7.0 to v1.10.0. [GH-35](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/35)
- Updated `VMware.PowerCLI` from v12.4.1 to v12.7.0. [GH-35](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/35)
- Updated `VMware.vSphere.SsoAdmin` from v1.3.7 to v1.3.8. [GH-35](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/35)

## [v1.0.4](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/releases/tag/v1.0.4)

> Release Date: 2022-10-10

Initial availability of the PowerShell module for VMware Cloud Foundation Reporting.
