# Generating Alert Reports

The [`Invoke-VcfAlertReport`](../../functions/Invoke-VcfAlertReport) cmdlet generates a system alert report. This report collects information about the system alerts that are currently active in the VMware Cloud Foundation system for the platform components. This report reduces the need to login to multiple product interfaces to collect information about the system alerts.

## Only Issues

### VMware Cloud Foundation Instance

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a system alert report for SDDC Manager instance and run the commands in the PowerShell console.

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

3. Generate the report which only displays issues by running the command in the PowerShell console.

    ```powershell
    Invoke-VcfAlertReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -reportPath $reportPath -allDomains -failureOnly
    ```

4. Review the generated HTML report and perform remediation of any identified issues.

### Workload Domain

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a system alert report for SDDC Manager instance and run the commands in the PowerShell console.

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

3. Generate the report which only displays issues by running the command in the PowerShell console.

    ```powershell
    Invoke-VcfAlertReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -reportPath $reportPath -workloadDomain $workloadDomain -failureOnly
    ```

4. Review the generated HTML report and perform remediation of any identified issues.

## All Results

### VMware Cloud Foundation Instance

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a system alert report for SDDC Manager instance and run the commands in the PowerShell console.

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
    Invoke-VcfAlertReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -reportPath $reportPath -allDomains
    ```

4. Review the generated HTML report and perform remediation of any identified issues.

### Workload Domain

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation to generate a system alert report for SDDC Manager instance and run the commands in the PowerShell console.

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
    Invoke-VcfAlertReport -sddcManagerFqdn $sddcManagerFqdn -sddcManagerUser $sddcManagerUser -sddcManagerPass $sddcManagerPass -reportPath $reportPath -workloadDomain $workloadDomain
    ```

4. Review the generated HTML report and perform remediation of any identified issues.
