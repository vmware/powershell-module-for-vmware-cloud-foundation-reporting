# Generating Configuration Reports

The [`Invoke-VcfConfigReport`](../functions/Invoke-VcfConfigReport.md) cmdlet generates a configuration report. This report collects information about the configuration settings in a VMware Cloud Foundation system for the platform components. This report reduces the need to login to multiple product interfaces and endpoints to collect information about the configuration.

## VMware Cloud Foundation Instance

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a configuration report for SDDC Manager instance and run the commands in the PowerShell console.

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
    Invoke-VcfConfigReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -reportPath $reportPath -allDomains
    ```

4. Review the generated HTML report.

## Workload Domain

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a configuration report for SDDC Manager instance and run the commands in the PowerShell console.

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
    Invoke-VcfConfigReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -reportPath $reportPath -workloadDomain $workloadDomain
    ```

4. Review the generated HTML report.
