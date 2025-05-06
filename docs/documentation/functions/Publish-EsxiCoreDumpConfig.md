# Publish-EsxiCoreDumpConfig

## Synopsis

Generates an ESX core dump configuration report.

## Syntax

### All-WorkloadDomains

```powershell
Publish-EsxiCoreDumpConfig [-server] <String> [-user] <String> [-pass] <String> [-html] [-allDomains] [<CommonParameters>]
```

### Specific--WorkloadDomain

```powershell
Publish-EsxiCoreDumpConfig [-server] <String> [-user] <String> [-pass] <String> [-html] [-workloadDomain] <String> [<CommonParameters>]
```

## Description

The `Publish-EsxiCoreDumpConfig` cmdlet generates an ESX core dump report for a workload domain.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates that network connectivity is available to the SDDC Manager instance.
- Validates that network connectivity is available to the vCenter instance.
- Generates an ESX core dump report for all ESXi hosts in a workload domain.

## Examples

### Example 1

```powershell
Publish-EsxiCoreDumpConfig -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -alldomains
```

This example generates an ESX core dump report for all ESX hosts across the VMware Cloud Foundation instance.

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

### -html

Switch to output the report in HTML format.

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
Parameter Sets: Specific--WorkloadDomain
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
