# Request-VcenterStorageHealth

## Synopsis

Checks the disk usage on a vCenter instance.

## Syntax

```powershell
Request-VcenterStorageHealth [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-failureOnly] [<CommonParameters>]
```

## Description

The `Request-VcenterStorageHealth` cmdlets checks the disk space usage on a vCenter instance.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates network connectivity and authentication to the SDDC Manager instance.
- Validates network connectivity and authentication to the vCenter instance.
- Collects information for the disk usage.
- Checks disk usage against thresholds and outputs the results.

## Examples

### Example 1

```powershell
Request-VcenterStorageHealth -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name]
```

This example will check disk usage for a vCenter instance managed by SDDC Manager for a specified workload domain.

### Example 2

```powershell
Request-VcenterStorageHealth -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -allDomains -failureOnly
```

This example will check the disk usage for all vCenter instances managed by SDDC Manager but only reports issues.

## Parameters

### -server

The fully qualified domain name of the SDDC Manager.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
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
Position: 2
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
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -domain

The name of the workload domain to run against.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 4
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
