# Generating an Upgrade Precheck Report

The [`Invoke-VcfUpgradePrecheck`](../../functions/Invoke-VcfUpgradePrecheck) cmdlet initiates an upgrade precheck of a workload domain using the REST API and presents the results in an HTML report. This allows you to start the precheck from the PowerShell console.

## Start an Upgrade Precheck for a Workload Domain

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate an upgrade precheck report for SDDC Manager instance and run the commands in the PowerShell console.

    **Example**:

    === ":fontawesome-brands-windows: &nbsp; Windows"

        ```powershell
        --8<-- "./docs/snippets/vars-vcf.ps1"
        --8<-- "./docs/snippets/vars-domain.ps1"
        --8<-- "./docs/snippets/vars-windows.ps1"
        ```

    === ":fontawesome-brands-linux: &nbsp; Linux"

        ```powershell
        --8<-- "./docs/snippets/vars-vcf.ps1"
        --8<-- "./docs/snippets/vars-domain.ps1"
        --8<-- "./docs/snippets/vars-linux.ps1"
        ```
3. Generate the report by running the command in the PowerShell console.

    ```powershell
    Invoke-VcfUpgradePrecheck -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -reportPath $reportPath -workloadDomain $workloadDomain
    ```

4. Review the generated HTML report.
