# Request-EsxiOverview

## SYNOPSIS

Returns overview of ESXi hosts.

## SYNTAX

```powershell
Request-EsxiOverview [-server] <String> [-user] <String> [-pass] <String> [-anonymized] [-subscription]
 [[-outputCsv] <String>] [<CommonParameters>]
```

## DESCRIPTION

The Request-EsxiOverview cmdlet returns an overview of the ESXi host managed by SDDC Manager.
The cmdlet connects to the SDDC Manager using the -server, -user, and -pass values:

- Validates that network connectivity and authentication to the SDDC Manager instance
- Validates that network connectivity and authentication to the vCenter Server instances
- Collects the ESXi host overview detail

## EXAMPLES

### EXAMPLE 1

```powershell
Request-EsxiOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
```

This example will return an overview of the ESXi hosts managed by the SDDC Manager instance.

### EXAMPLE 2

```powershell
Request-EsxiOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -subscription
```

This example will return an overview of the ESXi hosts managed by the SDDC Manager instance with the number of cores for VCF+ subscription.

### EXAMPLE 3

```powershell
Request-EsxiOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -subscription -outputCsv F:\Reporting
```

This example will return an overview of the ESXi hosts managed by the SDDC Manager instance with the number of cores for VCF+ subscription and save as a CSV file to F:\Reporting.
```

### EXAMPLE 4

```powershell
Request-EsxiOverview -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -anonymized
```

This example will return an overview of the ESXi hosts managed by the SDDC Manager instance, but will anonymize the output.

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
