# Release History

## v2.7.0

> Release Date: 2025-05-22

Documentation:

- Updated documentation to use example context. (#242, #243, #245, #246, #247, #248, #249, #250, #251, #252, #253, #254, #255, #256, #257, #258, #259, #260, #261, #262, #263)

Chore:

- Updated `VMware.PowerCLI` module dependency from v13.2.1 to v13.3.0. [#217](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/217)
- Updated `PowerValidatedSolutions` module dependency from v2.11.0 to v2.12.1. [#217](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/217)
- Updated code of conduct, contributing, license, workflows, etc. (#234, #235, #236, #237, #238, #239, #240, #241)

## v2.6.3

> Release Date: 2024-07-24

Enhancement:

- Adds support for VMware Cloud Foundation 5.2. [#217](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/217)

Bugfix:

- Updates `Request-DatastoreStorageCapacity` to handle datastores with a size of 0. [#217](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/217)

Chore:

- Updated `PowerValidatedSolutions` from v2.10.0 to v2.11.0. [#226](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/226)

## v2.6.2

> Release Date: 2024-05-28

Bugfix:

- Updated `Invoke-VcfHealthReport` cmdlet to handle `.` or `-` in the report path. [#217](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/217)
- Updated `Invoke-VcfAlertReport` cmdlet to handle `.` or `-` in the report path. [#217](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/217)
- Updated `Invoke-VcfConfigReport` cmdlet to handle `.` or `-` in the report path. [#217](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/217)
- Updated `Invoke-VcfUpgradePrecheck` cmdlet to handle `.` or `-` in the report path. [#217](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/217)
- Updated `Invoke-VcfOverviewReport` cmdlet to handle `.` or `-` in the report path. [#217](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/217)

Chore:

- Updated `VMware.PowerCLI` from v13.1.0 to v13.2.1 [#218](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/218)
- Updated `PowerValidatedSolutions` from v2.8.0 to v2.10.0. [#218](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/218)

## v2.6.1

> Release Date: 2024-02-06

Bugfix:

- Updated `Request-VcenterStorageHealth` cmdlet to output an error message if authentication to vCenter Server fails. [#209](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/209)

## v2.6.0

> Release Date: 2024-01-30

Enhancement:

- Updated `Publish-VmConnectedCdrom` function to generate JSON output. [#204](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/204)
- Updated `Publish-EsxiConnectionHealth` function to generate JSON output. [#204](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/204)
- Updated `Publish-SddcManagerFreePool` function to generate JSON output. [#204](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/204)

Chore:

- Updated `PowerVCF` from v2.4.0 to v2.1.0. [#206](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/206)
- Updated `PowerValidatedSolutions` from v2.7.0 to v2.8.0. [#206](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/206)

## v2.5.0

> Release Date: 2023-12-15

Breaking Change:

- Removes support for Microsoft Windows PowerShell 5.1. Please use Microsoft PowerShell 7.2.0 or later. [#200](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/200)

Enhancement:

- Added a prerequisite check to `Invoke-VcfHealthReport` function to verify that the tar utility is present on Windows if using Windows PowerShell 5.1 (Desktop) or PowerShell 7 (Core). The `tar` utility is included with Windows Server 2019 and later and is noted as a system requirement in the documentation. [#191](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/191)
- Added support for use of secure strings for sensitive parameters. [#199](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/199)

Chore:

- Updated `PowerVCF` from v2.3.0 to v2.4.0. [#200](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/200)
- Updated `PowerValidatedSolutions` from v2.6.0 to v2.7.0. [#200](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/200)

## v2.4.2

> Release Date: 2023-10-18

Bugfix:

- Updated `Start-Create*` and `Invoke-*` functions to address file path generation issues in Linux. [#182](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/182)

## v2.4.1

> Release Date: 2023-09-25

Chore:

- Updated code to use `Join-Path` for file paths to simplify the code and better support Windows and Linux.

## v2.4.0

> Release Date: 2023-08-29

Bugfix:

- Updated `Request-VcenterStorageHealth` to exclude `/dev/mapper/archive_vg-archive` from the output per [KB 76563](https://kb.vmware.com/s/article/76563). [#167](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/167)

Chore:

- Updated `VMware.PowerCLI` from v13.0.0 to v13.1.0. [#171](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/171)
- Updated `PowerValidatedSolutions` from v2.5.0 to v2.6.0. [#171](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/171)
- Added PowerShell Gallery downloads badge to the `docs/index.md` [#171](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/171)

## v2.3.0

> Release Date: 2023-07-25

Enhancement:

- Added the `RequiredModules` key to the module manifest to specify the minimum dependencies required to install and run the PowerShell module. [#155](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/155)
- Updated `Test-VcfReportingPrereq` to verify that the minimum dependencies are met to run the PowerShell module based on the module's manifest. [#155](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/155)

Chore:

- Updated `PowerValidatedSolutions` from v2.4.0 to v2.5.0. [#155](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/155)

## v2.2.0

> Release Date: 2023-06-27

Bugfix:

- Updates `Publish-StorageCapacityHealth` to correct [#147](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/issues/147). [#148](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/148)

Chore:

- Updated `PowerValidatedSolutions` from v2.3.0 to v2.4.0. [#150](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/150)

## v2.1.0

> Release Date: 2023-05-30

Bugfix:

- Updates `Publish-NsxtTier0BgpStatus` to correctly format the HTML output if the NSX Tier-0 is not configured for BGP. [#134](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/134)

Enhancement:

- Added `Publish-HardwareCompatibilityHealth` to return the hardware compatibility health from the SoS Health Summary JSON data. [#129](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/129)
- Updated `Invoke-VcfHealthReport` to include the hardware compatibility health using the `Publish-HardwareCompatibilityHealth` cmdlet. [#129](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/129)
- Added component size checks for vCenter Server instances and NSX Local Manager clusters to the overview report. [#130](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/130)
- Added `Publish-PingConnectivityHealth` to return the ping connectivity health from the SoS Health Summary JSON data. [#132](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/132)
- Updated `Publish-ComponentConnectivityHealth` to include the ping connectivity health using the `Publish-PingConnectivityHealth` cmdlet. [#132](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/132)

Refactor:

- Updated `Request-VcenterAuthentication` to support isolated workload domains. [#131](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/131)
- Updated `Request-DatastoreStorageCapacity` to support isolated workload domains. [#131](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/131)

Chore:

- Updated the NSX product name and terms. [#135](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/135)
- Added `.PARAMETER` entries for user-facing functions. [#141](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/141)

## v2.0.1

> Release Date: 2023-05-12

Bug Fix:

- Updated `Request-SoSHealthJson` to omit the `precheckReport` and `versionHealth` from the SoS API request payload if the version is not VMware Cloud Foundation 4.5.0 or later.

## v2.0.0

> Release Date: 2023-04-25

Enhancement:

- Updated `Publish-CertificateHealth` with thresholds based on certificate expiration. [#107](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/107)
- Updated `Publish-CertificateHealth` to include an "Expires In (Days)" column. [#107](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/107)
- Updated `Publish-CertificateHealth` to include ESXi host certificates. [#107](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/107)
- Updated `Publish-PasswordHealth` to include an "Expires In (Days)" column. [#111](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/111)
- Added `Publish-VersionHealth` to return the version health from the SoS Health Summary JSON data. [#123](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/123)
- Updated `Invoke-VcfHealthReport` to include the version health using the `Publish-VersionHealth` cmdlet. [#123](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/123)
- Added `Show-ReportingOutput` cmdlet to format output to the console when `PowerVCF` is not installed. [#121](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/121)
- Updated `Publish-VsanHealth` to include the results for capacity utilization and the active resync of objects [#124](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/124)
- Updated `Publish-VsanHealth` to include the results for stretched cluster health and stretched cluster tests. [#126](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/126)

Refactor:

- **Breaking**: Updated `Invoke-VcfReportingPrereq` to:
  - Use `-sddcManagerFqdn`, `sddcManagerUser`, and `sddcManagerPass` parameters to check the SDDC Manager version. [#117](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/117)
  - Use `Write-LogMessage` to apply colors to the output and log the output to a file using the `-logPath` parameter. [#117](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/117)
- **Breaking**: Updated `Invoke-VcfHealthReport` to use `-sddcManagerLocalUser` and `-sddcManagerLocalPass` parameters instead of `-SddcManagerRootPass`. Examples use the local `vcf` user account for the SDDC Manager virtual appliance. [#113](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/113)
- **Breaking**: Updated `Publish-StorageCapacityHealth` to use `-localUser` and `-localPass` parameters instead of `-rootPass`. Examples use the local `vcf` user account for the SDDC Manager virtual appliance. [#113](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/113)
- **Breaking**: Updated `Request-SddcManagerStorageHealth` to use `-localUser` and `-localPass` parameters instead of `-rootPass`. Examples use the local `vcf` user account for the SDDC Manager virtual appliance. [#113](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/113)
- **Breaking**: Removed `Invoke-VcfPasswordPolicy` and supporting content. Please use the [`VMware.CloudFoundation.PasswordManagement`](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-password-management) module. [#118](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/118)
- **Breaking**: Renamed `Request-VrealizeOverview` to `Request-VMwareAriaSuiteOverview` and updated outputs to the rebranded product names. [#128](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/128)
- Updated `Request-SoSHealthJson` to use the API to retrieve the SoS Health Summary JSON results. [#102](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/102)
- Updated `Publish-PasswordHealth` to return the results from the SoS Health Summary JSON data. [#111](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/111)
- Updated `Invoke-VcfHealthReport` to use the `Publish-PasswordHealth` cmdlet. [#111](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/111)
- Removed `Publish-LocalUserExpiry` and supporting functions in favor of the `Publish-PasswordHealth` cmdlet. [#111](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/111)
- Removed `Request-LocalUserExpiry` which supported the `Publish-LocalUserExpiry` cmdlet. Results are now returned from the SoS Health Summary JSON data. [#120](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/120)
- Removed `Request-SddcManagerUserExpiry` which supported the `Publish-LocalUserExpiry` cmdlet. [#120](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/120)
- Removed `Request-vCenterUserExpiry` which supported the `Publish-LocalUserExpiry` cmdlet. [#120](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/120)
- Removed `Request-NsxtManagerUserExpiry` which supported the `Publish-LocalUserExpiry` cmdlet. [#120](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/120)
- Removed `Request-NsxtEdgeUserExpiry` which supported the `Publish-LocalUserExpiry` cmdlet. [#120](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/120)
- Removed `Request-Request-vRslcmUserExpiry` which supported the `Publish-LocalUserExpiry` cmdlet. [#120](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/120)

Chore:

- Updated `PowerVCF` from v2.2.0 to v2.3.0. [#125](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/125)
- Updated `PowerValidatedSolutions` from v2.0.1 to v2.2.0. [#117](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/117)
- Updated `VMware.PowerCLI` from v12.7.0 to v13.0.0. [#117](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/117)
- Updated `VMware.vSphere.SsoAdmin` from v1.3.8 to v1.3.9. [#117](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/117)

## v1.1.0

> Release Date: 2023-02-28

Bugfix:

- Updated `Request-VcenterBackupStatus` backup message to remove the SDDC Manager FQDN when backups are located on the SDDC Manager. Required for Health Monitoring and Reporting solution alerts. [#95](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/95)
- Updated `Publish-vCenterHealth` to correctly link and display the vCenter Server Ring Topology Health from SoS. [#94](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/94)
- Resolves an issue with the display name of the vRealize Log Insight product name in the `Request-VrealizeOverview`due to an upstream error in the `.SYNOPSIS` of `Get-VCFvRLI` in `PowerVCF`. [#86](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/86)
- Updated `Test-VcfReportingPrereq` to return results when run on Photon OS. [#82](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/82)

Enhancements:

- Updated `Publish-*` cmdlets to support JSON generation. Required for Health Monitoring and Reporting solution. [#79](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/79)
  - `Publish-BackupStatus`
  - `Publish-NsxtTransportNodeStatus`
  - `Publish-NsxtTier0BgpStatus`
  - `Publish-SnapshotStatus`
  - `Publish-LocalUserExpiry`
  - `Publish-StorageCapacityHealth`
- Added `Publish-NsxtHealthNonSOS` and `Publish-ComponentConnectivityHealthNonSOS` cmdlets. Required for Health Monitoring and Reporting solution. [#79](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/79)
- Updated in `Publish-*` cmdlets that support JSON generation to specify encoding needed for Python to read it the content. Required for Health Monitoring and Reporting solution alerts. [#93](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/93)
- Added CPU Cores per Socket to the ESXi Host Overview on the overview report. [#85](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/85)
- Added an option to `Request-ESXiOverview` to report on the VCF+ subscription cores and export the results to CSV. [#87](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/87)

Documentation:

- Updated `README.md` to remove the **Known Issues** section and adds references to the GitHub issue tracker for support. [#88](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/88)
- Updated `README.md` documentation to include support for DellEMC VxRAIL. [#98](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/98)

Chore:

- Removed the password policy functions that were moved to `PowerValidatedSolutions` v2.0.0. [#100](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/100)
- Updated `PowerValidatedSolutions` from v2.0.0 to v2.0.1. [#99](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/99)

## v1.0.6

> Release Date: 2023-01-31

Bugfix:

- Updated `Request0VcenterOverview` to use the PowerVCF cmdlets to return the workload domain's cluster and host counts from the SDDC Manager inventory versus directly from the vSphere inventory. This will ensure that the host count does not include any HCX nodes. [#65](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/65)
- Updated `Publish-NsxtCombinedHealth` to use `$json` when calling `Publish-NsxtHealth`. [#59](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/59)
- Updated `Request-NsxtEdgeUserExpiry` to resolve error if an NSX Edge `root` password is different from an NSX Manager `root` password. [#75](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/75)

Enhancement:

- Updated `Invoke-VcfPasswordPolicy` cmdlet with new password expiration, complexity and account lockout details. [#53](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/53)

Documentation:

- Added a section for **Updating the Module** to the `README.md` documentation. [#57](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/57)

Chore:

- Updated `PowerValidatedSolutions` from v1.10.0 to v2.0.0. [#35](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/35)

Refactor:

- Refactored `Publish-StorageCapacityHealth` for code efficiency. [#64](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/64)
- Refactored `Invoke-VcfPasswordPolicy` for code efficiency. [#63](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/63)
- Refactored `Invoke-VcfConfigReport` for code efficiency. [#62](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/62)
- Refactored `Invoke-VcfAlertReport` for code efficiency. [#61](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/61)
- Refactored `Invoke-VcfHealthReport` for code efficiency. [#60](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/60)
- Transferred `Publish-EsxiPasswordPolicy` to `PowerValidatedSolutions` module. [#55](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/55)

## v1.0.5

> Release Date: 2022-12-20

Bugfix:

- Updated `Request-NsxtVidmStatus` and `Request-NsxtComputeManagerStatus` functions to resolve an issue supporting workload domains with shared NSX Local Managers on the health report. [#25](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/25)
- Updated `Request-NsxtComputeManagerStatus` function to resolve an issue with supporting workload domains with shared NSX Local Managers on the health report; a false negative for "rogue" compute managers (vCenter Server instances) registered in NSX Local Managers. [#42](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/42)
- Updated `Publish-CertificateHealth` function to resolve an issue accurately displaying the certificate health on the health report. [#43](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/43)
- Updated `Request-SddcManagerFreePool` function to resolve an issue returning the free pool health for the Health report if the ESXi host license is expired. [#32](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/32)
- Updated `Test-VcfReportingPrereq` to display an error on the PowerShell console if the version of a PowerShell module dependency does not meet the minimum requirements. [#35](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/35)

Enhancement:

- Added support for including the number of ESXi hosts per cluster in the system overview Report. [#46](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/46)
- Added `Request-EsxiOverview` and updates `Publish-VcfSystemOverview` functions to return the high-level status of each ESXi host on the system overview report. [#33](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/33)
- Added support for vRealize Log Insight, vRealize Operations, vRealize Automation, and Workspace ONE Access in the `Request-LocalUserExpiry` function. [#32](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/31)
- Removed the `Test-VcfReportingPrereq` from the `Invoke-*` function which reduces report initialization time. [#24](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/24)
- Updated `Test-VcfReportingPrereq` to display the version of an installed PowerShell module dependency. [#27](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/27)

Refactor:

- Replaces local `getNsxtServerDetail` function with `Get-NsxtServerDetail` function exported from `PowerValidatedSolutions`. [#35](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/35)

Chore:

- Updated `PowerValidatedSolutions` from v1.7.0 to v1.10.0. [#35](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/35)
- Updated `VMware.PowerCLI` from v12.4.1 to v12.7.0. [#35](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/35)
- Updated `VMware.vSphere.SsoAdmin` from v1.3.7 to v1.3.8. [#35](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-reporting/pull/35)

## v1.0.4

> Release Date: 2022-10-10

Initial availability of the PowerShell module for VMware Cloud Foundation Reporting.
