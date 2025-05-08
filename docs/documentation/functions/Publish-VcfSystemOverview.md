# Publish-VcfSystemOverview

## Synopsis

Publishs a system overview report.

## Syntax

```powershell
Publish-VcfSystemOverview [-server] <String> [-user] <String> [-pass] <String> [-anonymized] [<CommonParameters>]
```

## Description

The `Publish-VcfSystemOverview` cmdlet returns an overview of the Vmware Cloud Foundation instance.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates that network connectivity is available to the SDDC Manager instance.
- Collects the system overview details from the environment.

## Examples

### Example 1

```powershell
Publish-VcfSystemOverview -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password]
```

This example will return system overview report for all workload domains.

### Example 2

```powershell
Publish-VcfSystemOverview -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -anonymized
```

This example will return system overview report for all workload domains, but with anonymized data.

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

### -anonymized

Switch to enable anonymized output for the report.

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
