# Request-EsxiOverview

## Synopsis

Returns an overview of ESX hosts.

## Syntax

```powershell
Request-EsxiOverview [-server] <String> [-user] <String> [-pass] <String> [-anonymized] [-subscription] [[-outputCsv] <String>] [<CommonParameters>]
```

## Description

The `Request-EsxiOverview` cmdlet returns an overview of the ESX hosts managed by SDDC Manager.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates that network connectivity and authentication to the SDDC Manager instance.
- Validates that network connectivity and authentication to the vCenter instances.
- Collects the ESX host overview detail.

## Examples

### Example 1

```powershell
Request-EsxiOverview -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password]
```

This example will return an overview of the ESX hosts managed by the SDDC Manager instance.

### Example 2

```powershell
Request-EsxiOverview -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -subscription
```

This example will return an overview of the ESX hosts managed by the SDDC Manager instance with the number of cores for VCF+ subscription.

### Example 3

```powershell
Request-EsxiOverview -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -subscription -outputCsv [report_path]
```

This example will return an overview of the ESX hosts managed by the SDDC Manager instance with the number of cores for VCF+ subscription and save as a CSV file to the specified report path.

### Example 4

```powershell
Request-EsxiOverview -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -anonymized
```

This example will return an overview of the ESX hosts managed by the SDDC Manager instance, but will anonymize the output.

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

### -subscription

Switch to enable subscription output for the report.

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

### -outputCsv

The path to save the output as a CSV file.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable.` For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
