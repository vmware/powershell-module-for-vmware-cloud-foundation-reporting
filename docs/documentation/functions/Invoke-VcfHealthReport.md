# Invoke-VcfHealthReport

## Synopsis

Perform health checks for a VMware Cloud Foundation instance or workload domain.


## Syntax

### All-WorkloadDomains

```powershell
Invoke-VcfHealthReport -sddcManagerFqdn <String> -sddcManagerUser <String> -sddcManagerPass <String> -sddcManagerLocalUser <String> -sddcManagerLocalPass <String> -reportPath <String> [-allDomains] [-failureOnly] [-darkMode] [<CommonParameters>]
```

### Specific-WorkloadDomain

```powershell
Invoke-VcfHealthReport -sddcManagerFqdn <String> -sddcManagerUser <String> -sddcManagerPass <String> -sddcManagerLocalUser <String> -sddcManagerLocalPass <String> -reportPath <String> -workloadDomain <String> [-failureOnly] [-darkMode] [<CommonParameters>]

```

## Description

The `Invoke-VcfHealthReport` provides a single cmdlet to perform health checks across a VMware Cloud Foundation instance.

## Examples

### Example 1

```powershell
Invoke-VcfHealthReport -sddcManagerFqdn [sddc_manager_fqdn] -sddcManagerUser [admin_username] -sddcManagerPass [admin_password] -sddcManagerLocalUser [local_username] -sddcManagerLocalPass [local_password] -reportPath [report_path] -allDomains
```

This example runs a health check across a VMware Cloud Foundation instance.

### Example 2

```powershell
Invoke-VcfHealthReport -sddcManagerFqdn [sddc_manager_fqdn] -sddcManagerUser [admin_username] -sddcManagerPass [admin_password] -sddcManagerLocalUser [local_username] -sddcManagerLocalPass [local_password] -reportPath [report_path] -workloadDomain [workload_domain_name]
```

This example runs a health check for a specific workload domain within a VMware Cloud Foundation instance.

### Example 3

```powershell
Invoke-VcfHealthReport -sddcManagerFqdn [sddc_manager_fqdn] -sddcManagerUser [admin_username] -sddcManagerPass [admin_password] -sddcManagerLocalUser [local_username] -sddcManagerLocalPass [local_password] -reportPath [report_path] -allDomains -failureOnly
```

This example runs a health check across a VMware Cloud Foundation instance but only ouputs issues to the HTML report.

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

### -sddcManagerLocalUser

The username to authenticate to the SDDC Manager appliance.

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

### -sddcManagerLocalPass

The password to authenticate to the SDDC Manager appliance.

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

Switch to run health checks across all workload domains.

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

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
