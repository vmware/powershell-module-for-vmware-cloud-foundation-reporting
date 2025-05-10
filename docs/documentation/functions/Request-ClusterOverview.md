# Request-ClusterOverview

## Synopsis

Returns an overview of vSphere.

## Syntax

```powershell
Request-ClusterOverview [-server] <String> [-user] <String> [-pass] <String> [-anonymized] [<CommonParameters>]
```

## Description

The `Request-ClusterOverview` cmdlet returns an overview of the vSphere environment managed by SDDC Manager.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates that network connectivity and authentication to the SDDC Manager instance.
- Validates that network connectivity and authentication to the vCenter instances.
- Collects the vSphere overview detail.

## Examples

### Example 1

```powershell
Request-ClusterOverview -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password]
```

This example will return an overview of the vSphere environment managed by the SDDC Manager instance.

### Example 2

```powershell
Request-ClusterOverview -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -anonymized
```

This example will return an overview of the vSphere environment managed by the SDDC Manager instance, but will anonymize the output.

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
