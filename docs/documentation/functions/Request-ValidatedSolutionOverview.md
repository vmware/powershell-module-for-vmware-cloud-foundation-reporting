# Request-ValidatedSolutionOverview

## Synopsis

Returns VMware Validated Solution overview.

## Syntax

```powershell
Request-ValidatedSolutionOverview [-server] <String> [-user] <String> [-pass] <String> [<CommonParameters>]
```

## Description

The `Request-ValidatedSolutionOverview` cmdlet returns an overview of VMware Validated Solutions that are deployed.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates that network connectivity is available to the SDDC Manager instance.
- Collects the VMware Validated Solution details.

## Examples

### Example 1

```powershell
Request-ValidatedSolutionOverview -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password]
```

This example will return an overview of VMware Validated Solutions that are deployed.

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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable.` For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
