# Publish-ConnectivityHealth

## Synopsis

Formats the connectivity health data from the SOS JSON output.

## Syntax

```powershell
Publish-ConnectivityHealth [-json] <String> [-html] [-failureOnly] [<CommonParameters>]
```

## Description

The `Publish-ConnectivityHealth` cmdlet formats the connectivity health data from the SOS JSON output and publishes it as either a standard PowerShell object or an HTML object.

## Examples

### Example 1

```powershell
Publish-ConnectivityHealth -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password]
```

This example extracts and formats the connectivity health data as a PowerShell object from the JSON file.

### Example 2

```powershell
Publish-ConnectivityHealth -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -html
```

This example extracts and formats the connectivity health data as an HTML object from the JSON file.

### Example 3

```powershell
Publish-ConnectivityHealth -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -failureOnly
```

This example extracts and formats the connectivity health data as a PowerShell object from the JSON file for only the failed items.

## Parameters

### -json

The path to the JSON file containing the SOS health summary data.

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

### -html

Specifies that the output should be formatted as an HTML object.

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
