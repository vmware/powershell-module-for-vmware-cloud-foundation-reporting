# Generating Health Reports

The [`Invoke-VcfHealthReport`](../../functions/Invoke-VcfHealthReport) cmdlet generates a health report. This report combines the SoS Utility health checks with additional health checks not presently available in the SoS Utility. The report contains detailed information about the health of the VMware Cloud Foundation system and its components.

## Only Issues

### VMware Cloud Foundation Instance

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a health report for SDDC Manager instance and run the commands in the PowerShell console.

    **Example**:

    === ":fontawesome-brands-windows: &nbsp; Windows"

        ```powershell
        --8<-- "./docs/snippets/vars-vcf.ps1"
        --8<-- "./docs/snippets/vars-health.ps1"
        --8<-- "./docs/snippets/vars-windows.ps1"
        ```

    === ":fontawesome-brands-linux: &nbsp; Linux"

        ```powershell
        --8<-- "./docs/snippets/vars-vcf.ps1"
        --8<-- "./docs/snippets/vars-health.ps1"
        --8<-- "./docs/snippets/vars-linux.ps1"
        ```

3. Generate the report which only displays issues by running the command in the PowerShell console.

    ```powershell
    Invoke-VcfHealthReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -sddcManagerLocalUser $sddcManagerLocalUser -sddcManagerLocalPass $sddcManagerLocalPass -reportPath $reportPath -allDomains -failureOnly
    ```

4. Review the generated HTML report and perform remediation of any identified issues.

### Workload Domain

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a health report for SDDC Manager instance and run the commands in the PowerShell console.

    **Example**:

    === ":fontawesome-brands-windows: &nbsp; Windows"

        ```powershell
        --8<-- "./docs/snippets/vars-vcf.ps1"
        --8<-- "./docs/snippets/vars-health.ps1"
        --8<-- "./docs/snippets/vars-domain.ps1"
        --8<-- "./docs/snippets/vars-windows.ps1"
        ```

    === ":fontawesome-brands-linux: &nbsp; Linux"

        ```powershell
        --8<-- "./docs/snippets/vars-vcf.ps1"
        --8<-- "./docs/snippets/vars-health.ps1"
        --8<-- "./docs/snippets/vars-domain.ps1"
        --8<-- "./docs/snippets/vars-linux.ps1"
        ```

3. Generate the report which only displays issues by running the command in the PowerShell console.

    ```powershell
    Invoke-VcfHealthReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -sddcManagerLocalUser $sddcManagerLocalUser -sddcManagerLocalPass $sddcManagerLocalPass -reportPath $reportPath -workloadDomain $workloadDomain -failureOnly
    ```

4. Review the generated HTML report and perform remediation of any identified issues.

## All Results

### VMware Cloud Foundation Instance

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a health report for SDDC Manager instance and run the commands in the PowerShell console.

    **Example**:

    === ":fontawesome-brands-windows: &nbsp; Windows"

        ```powershell
        --8<-- "./docs/snippets/vars-vcf.ps1"
        --8<-- "./docs/snippets/vars-health.ps1"
        --8<-- "./docs/snippets/vars-windows.ps1"
        ```

    === ":fontawesome-brands-linux: &nbsp; Linux"

        ```powershell
        --8<-- "./docs/snippets/vars-vcf.ps1"
        --8<-- "./docs/snippets/vars-health.ps1"
        --8<-- "./docs/snippets/vars-linux.ps1"
        ```

3. Generate the report by running the command in the PowerShell console.

    ```powershell
    Invoke-VcfHealthReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -sddcManagerLocalUser $sddcManagerLocalUser -sddcManagerLocalPass $sddcManagerLocalPass -reportPath $reportPath -allDomains
    ```

4. Review the generated HTML report and perform remediation of any identified issues.

### Workload Domain

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a health report for SDDC Manager instance and run the commands in the PowerShell console.

    **Example**:

    === ":fontawesome-brands-windows: &nbsp; Windows"

        ```powershell
        --8<-- "./docs/snippets/vars-vcf.ps1"
        --8<-- "./docs/snippets/vars-health.ps1"
        --8<-- "./docs/snippets/vars-domain.ps1"
        --8<-- "./docs/snippets/vars-windows.ps1"
        ```

    === ":fontawesome-brands-linux: &nbsp; Linux"

        ```powershell
        --8<-- "./docs/snippets/vars-vcf.ps1"
        --8<-- "./docs/snippets/vars-health.ps1"
        --8<-- "./docs/snippets/vars-domain.ps1"
        --8<-- "./docs/snippets/vars-linux.ps1"
        ```

3. Generate the report by running the command in the PowerShell console.

    ```powershell
    Invoke-VcfHealthReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -sddcManagerLocalUser $sddcManagerLocalUser -sddcManagerLocalPass $sddcManagerLocalPass -reportPath $reportPath -workloadDomain $workloadDomain
    ```

4. Review the generated HTML report and perform remediation of any identified issues.
