# Publish-EsxiAlert

## Synopsis

Publish system alerts/alarms from ESX hosts in a vCenter instance managed by SDDC Manager.

## Syntax

### All-WorkloadDomains

```powershell
Publish-EsxiAlert [-server] <String> [-user] <String> [-pass] <String> [-allDomains] [-failureOnly] [<CommonParameters>]
```

### Specific-WorkloadDomain

```powershell
Publish-EsxiAlert [-server] <String> [-user] <String> [-pass] <String> [-workloadDomain] <String> [-failureOnly] [<CommonParameters>]
```

## Description

The `Publish-EsxiAlert` cmdlet returns all alarms from ESX hosts managed by SDDC Manager.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates that network connectivity is available to the vCenter instance
- Validates the authentication to vCenter with credentials from SDDC Manager
- Collects the alerts from all ESX hosts in a vCenter instance

## Examples

### Example 1

```powershell
Publish-EsxiAlert -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -allDomains
```

This example will return alarms from all ESX hosts in vCenter managed by SDDC Manager for a all workload domains.

### Example 2

```powershell
Publish-EsxiAlert -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -allDomains -failureOnly
```

This example will return alarms from all ESX hosts in vCenter managed by SDDC Manager for a all workload domains but only for the failed items.

### Example 3

```powershell
Publish-EsxiAlert -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -workloadDomain [workload_domain_name]
```

This example will return alarms from all ESX hosts in vCenter managed by SDDC Manager for a workload domain named [workload_domain_name].

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

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
