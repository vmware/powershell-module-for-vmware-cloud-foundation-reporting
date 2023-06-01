# Request-VcfOverview

## SYNOPSIS

Returns System Overview.

## SYNTAX

```powershell
Request-VcfOverview [-server] <String> [-user] <String> [-pass] <String> [-anonymized] [<CommonParameters>]
```

## DESCRIPTION

The Request-VcfOverview cmdlet returns an overview of the SDDC Manager instance.
The cmdlet connects to the SDDC Manager using the -server, -user, and -pass values:

- Validates that network connectivity is available to the SDDC Manager instance
- Collects the overview detail

## EXAMPLES

### EXAMPLE 1

```powershell
Request-VcfOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
```

This example will return an overview of the SDDC Manager instance.

### EXAMPLE 2

```powershell
Request-VcfOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -anonymized
```

This example will return an overview of the SDDC Manager instance, but will anonymize the output.

## PARAMETERS

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
