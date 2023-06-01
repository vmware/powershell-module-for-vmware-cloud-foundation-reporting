# Installing the Module

Verify that your system has a [supported edition and version](/powershell-module-for-vmware-cloud-foundation-reporting/#powershell) of PowerShell installed.

Install the PowerShell [module dependencies](/powershell-module-for-vmware-cloud-foundation-reporting/#module-dependencies) from the PowerShell Gallery by running the following commands:

```powershell
--8<-- "./docs/snippets/install-module.ps1"
```

If using PowerShell Core, import the modules before proceeding:

For example:

```powershell
--8<-- "./docs/snippets/import-module.ps1"
```

To verify the module dependencies are installed, run the following commands in the PowerShell console.

**Example**:

```powershell
--8<-- "./docs/snippets/vars-vcf.ps1"
Test-VcfReportingPrereq -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass
```

:material-information-slab-circle: &nbsp; [Reference](/powershell-module-for-vmware-cloud-foundation-reporting/documentation/functions/Test-VcfReportingPrereq/)

Once installed, any cmdlets associated with `VMware.CloudFoundation.Reporting` and the its dependencies will be available for use.

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
