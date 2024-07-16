# Installing the Module

Verify that your system has a [supported edition and version](index.md#powershell) of PowerShell installed.

=== ":material-pipe: &nbsp; Connected Environment"

    For environments connected to the Internet, you can install the [module dependencies](index.md#module-dependencies) from the PowerShell Gallery by running the following commands in the PowerShell console:

    ```powershell
    --8<-- "./docs/snippets/install-module.ps1"
    ```

    Import the modules before proceeding:

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

=== ":material-pipe-disconnected: &nbsp; Disconnected Environment"

    For environments disconnected from the Internet _(e.g., dark-site, air-gapped)_, you can save the [module dependencies](index.md#module-dependencies) from the PowerShell Gallery by running the following commands in the PowerShell console:

    === ":fontawesome-brands-windows: &nbsp; Windows"

        From a system with an Internet connection, save the module dependencies from the PowerShell Gallery by running the following commands in the PowerShell console:

        ```powershell
        --8<-- "./docs/snippets/save-module-local-windows.ps1"
        ```

        From the system with the Internet connection, copy the module dependencies to a target system by running the following commands in the PowerShell console:

        ```powershell
        --8<-- "./docs/snippets/copy-module-local-windows.ps1"
        ```

        On the target system, import the module dependencies by running the following commands in the PowerShell console:

        ```powershell
        --8<-- "./docs/snippets/import-module.ps1"
        ```

    === ":fontawesome-brands-linux: &nbsp; Linux"

        Prerequisite for module installation on Linux.

        ```bash
        --8<-- "./docs/snippets/pre-req-linux.sh"
        ```

        From a system with an Internet connection, save the module dependencies from the PowerShell Gallery by running the following commands in the PowerShell console:

        ```powershell
        --8<-- "./docs/snippets/save-module-local-linux.ps1"
        ```

        From the system with an Internet connection, copy the module dependencies to a target system by running the following commands in the PowerShell console:

        ```bash
        --8<-- "./docs/snippets/copy-module-local-linux.sh"
        ```

        On the target system, import the module dependencies by running the following commands in the PowerShell console:

        ```powershell
        --8<-- "./docs/snippets/import-module-local-linux.ps1"
        ```

:material-information-slab-circle: &nbsp; [Reference](./documentation/functions/Test-VcfReportingPrereq.md)

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
