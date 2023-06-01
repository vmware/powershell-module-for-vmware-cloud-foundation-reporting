# Request-SddcManagerSnapshotStatus

## SYNOPSIS

Request the snapshot status for the SDDC Manager.

## SYNTAX

```powershell
Request-SddcManagerSnapshotStatus [-server] <String> [-user] <String> [-pass] <String> [-failureOnly]
 [<CommonParameters>]
```

## DESCRIPTION

The Request-SddcManagerSnapshotStatus cmdlet checks the snapshot status for SDDC Manager.
The cmdlet connects to SDDC Manager using the -server, -user, and password values:

- Validates network connectivity and authenticaton to the SDDC Manager instance
- Gathers the details for the vCenter Server instance from the SDDC Manager
- Validates network connectivity and authentication to the vCenter Server instance
- Performs checks on the snapshot status and outputs the results

## EXAMPLES

### EXAMPLE 1

```powershell
Request-SddcManagerSnapshotStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
```

This example will publish the snapshot status for the SDDC Manager in a VMware Cloud Foundation instance.

### EXAMPLE 2

```powershell
Request-SddcManagerSnapshotStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -failureOnly
```

This example will publish the snapshot status for the SDDC Manager in a VMware Cloud Foundation instance, but for only failed items.

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
