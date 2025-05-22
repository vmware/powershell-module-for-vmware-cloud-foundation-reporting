# Invoke-VcfAlertReport

## Synopsis

Generates the alert report for a VMware Cloud Foundation instance.

## Syntax

### All-WorkloadDomains

```powershell
Invoke-VcfAlertReport [-sddcManagerFqdn] <String> [-sddcManagerUser] <String> [-sddcManagerPass] <String> [-reportPath] <String> [-allDomains] [-failureOnly] [-darkMode] [<CommonParameters>]
```

### Specific-WorkloadDomain

```powershell
Invoke-VcfAlertReport [-sddcManagerFqdn] <String> [-sddcManagerUser ]<String> [-sddcManagerPass] <String> [-reportPath] <String> [-workloadDomain] <String> [-failureOnly] [-darkMode] [<CommonParameters>]
```

## Description

The `Invoke-VcfAlertReport` provides a single cmdlet to generates the alert report for a VMware Cloud Foundation instance.

## Examples

### Example 1

```powershell
Invoke-VcfAlertReport -sddcManagerFqdn [sddc_manager_fqdn] -sddcManagerUser [admin_username] -sddcManagerPass [admin_password] -reportPath [report_path] -allDomains
```

This example generates the alert report across a VMware Cloud Foundation instance.

### Example 2

```powershell
Invoke-VcfAlertReport -sddcManagerFqdn [sddc_manager_fqdn] -sddcManagerUser [admin_username] -sddcManagerPass [admin_password] -reportPath [report_path] -allDomains -failureOnly
```

This example generates the alert report across a VMware Cloud Foundation instance but for only failed items.

### Example 3

```powershell
Invoke-VcfAlertReport -sddcManagerFqdn [sddc_manager_fqdn] -sddcManagerUser [admin_username] -sddcManagerPass [admin_password] -reportPath [report_path] -workloadDomain [workload_domain_name]
```

This example generates the alert report for a specific workload domain in a VMware Cloud Foundation instance.

### Example 4

```powershell
Invoke-VcfAlertReport -sddcManagerFqdn [sddc_manager_fqdn] -sddcManagerUser [admin_username] -sddcManagerPass [admin_password] -reportPath [report_path] -workloadDomain [workload_domain_name] -failureOnly
```

This example generates the alert report for a specific workload domain in a VMware Cloud Foundation instance but only reports issues.

## Parameters

### -sddcManagerFqdn

The fully qualified domain name of the SDDC Manager.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -sddcManagerUser

The username to authenticate to the SDDC Manager.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -sddcManagerPass

The password to authenticate to the SDDC Manager.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -reportPath

The path to save the policy report.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -allDomains

Switch to run against all workload domains.

```yaml
Type: SwitchParameter
Parameter Sets: All-WorkloadDomains
Aliases:

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -workloadDomain

The name of the workload domain to run against.

```yaml
Type: String
Parameter Sets: Specific-WorkloadDomain
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -failureOnly

Switch to only output issues to the report.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -darkMode

Switch to enable dark mode for the report.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable.` For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
