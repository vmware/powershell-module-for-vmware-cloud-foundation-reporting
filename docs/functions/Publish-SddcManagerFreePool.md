# Publish-SddcManagerFreePool

## SYNOPSIS

Publish SDDC Manager free pool health information in HTML format.

## SYNTAX

```powershell
Publish-SddcManagerFreePool [-server] <String> [-user] <String> [-pass] <String> [-failureOnly]
 [<CommonParameters>]
```

## DESCRIPTION

The Publish-SddcManagerFreePool cmdlet returns SDDC Manager free pool information in HTML format.
The cmdlet connects to the SDDC Manager using the -server, -user, and -pass values:

- Validates the network connectivity and authentication to the SDDC Manager instance
- Publishes information

## EXAMPLES

### EXAMPLE 1

```powershell
Publish-SddcManagerFreePool -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
```

This example will return the free pool health from SDDC Manager.

### EXAMPLE 2

```powershell
Publish-SddcManagerFreePool -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -failureOnly
```

This example will return the free pool health from SDDC Manager and return the failures only.

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
