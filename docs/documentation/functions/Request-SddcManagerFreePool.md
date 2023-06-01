# Request-SddcManagerFreePool

## SYNOPSIS

Returns the status of the ESXi hosts in the free pool.

## SYNTAX

```powershell
Request-SddcManagerFreePool [-server] <String> [-user] <String> [-pass] <String> [-failureOnly]
 [<CommonParameters>]
```

## DESCRIPTION

The Request-SddcManagerFreePool cmdlet returns status of the ESXi hosts in the free pool.
The cmdlet connects
to SDDC Manager using the -server, -user, and -pass values:

- Validates that network connectivity and authentication is possible to the SDDC Manager instance
- Gathers the details for the ESXi hosts in the free pool

## EXAMPLES

### EXAMPLE 1

```powershell
Request-SddcManagerFreePool -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
```

This example will return the ESXi hosts in the free pool managed by SDDC Manager for a workload domain.

### EXAMPLE 2

```powershell
Request-SddcManagerFreePool -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -failureOnly
```

This example will return the ESXi hosts in the free pool managed by SDDC Manager for a workload domain but only reports issues.

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

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
