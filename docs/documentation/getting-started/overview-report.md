# Generating an Overview Report

The [`Invoke-VcfOverviewReport`](../functions/Invoke-VcfOverviewReport.md) cmdlet generates a system overview report. This report contains high-level information about the VMware Cloud Foundation Instance. This report may be used to provide a quick system overview of the system to your VMware representative.

## Generate an Overview Report for a VMware Cloud Foundation Instance

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a system overview report for SDDC Manager instance and run the commands in the PowerShell console.

    **Example**:

    === ":fontawesome-brands-windows: &nbsp; Windows"

        ```powershell
        --8<-- "./docs/snippets/vars-vcf.ps1"
        --8<-- "./docs/snippets/vars-windows.ps1"
        ```

    === ":fontawesome-brands-linux: &nbsp; Linux"

        ```powershell
        --8<-- "./docs/snippets/vars-vcf.ps1"
        --8<-- "./docs/snippets/vars-linux.ps1"
        ```

3. Generate the report by running the command in the PowerShell console.

    ```powershell
    Invoke-VcfOverviewReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -reportPath $reportPath
    ```

    If you prefer to anonymize the data, you can use the `-anonymized` parameter.

    ```powershell
    Invoke-VcfOverviewReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -reportPath $reportPath -anonymized
    ```

4. Review the generated HTML report.
