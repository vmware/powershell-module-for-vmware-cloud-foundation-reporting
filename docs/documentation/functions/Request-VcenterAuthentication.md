# Request-VcenterAuthentication

## Synopsis

Checks API authentication to a vCenter instance.

## Syntax

### All-WorkloadDomains

```powershell
Request-VcenterAuthentication [-server] <String> [-user] <String> [-pass] <String> [-allDomains] [-failureOnly] [<CommonParameters>]
```

### Specific-WorkloadDomains

```powershell
Request-VcenterAuthentication [-server] <String> [-user] <String> [-pass] <String> [-workloadDomain] <String> [-failureOnly] [<CommonParameters>]
```

## Description

The `Request-VcenterAuthentication` cmdlets checks the authentication to a vCenter instance.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates that network connectivity is available to the SDDC Manager instance.
- Validates the authentication to vCenter with credentials from SDDC Manager.
- Validates that network connectivity is available to the vCenter instance.

## Examples

### Example 1

```powershell
Request-VcenterAuthentication -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -allDomains
```

This example will check authentication to vCenter API for all vCenter instances managed by SDDC Manager.

### Example 2

```powershell
Request-VcenterAuthentication -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -workloadDomain [workload_domain_name]
```

This example will check authentication to vCenter API for a specified workload domain.

### Example 3

```powershell
Request-VcenterAuthentication -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -allDomains -failureOnly
```

This example will check authentication to vCenter API for all vCenter instances managed by SDDC Manager but only reports issues.

## Parameters

### -server

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

### -user

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

### -pass

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
Parameter Sets: Specific-WorkloadDomains
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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable.` For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
