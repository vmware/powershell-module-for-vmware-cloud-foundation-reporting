# Request-VcenterAlert

## SYNOPSIS

Returns alarms from vCenter Server managed by SDDC Manager.

## SYNTAX

```powershell
Request-VcenterAlert [-server] <String> [-user] <String> [-pass] <String> [-domain] <String>
 [[-filterOut] <String>] [-failureOnly] [<CommonParameters>]
```

## DESCRIPTION

The Request-VcenterAlert cmdlet returns all alarms from vCenter Server managed by SDDC Manager.
The cmdlet connects to the SDDC Manager using the -server, -user, and -pass values:

- Validates that network connectivity is available to the vCenter Server instance
- Validates the authentication to vCenter Server with credentials from SDDC Manager
- Collects the alerts from vCenter Server

## EXAMPLES

### EXAMPLE 1

```powershell
Request-VcenterAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
```

This example will return alarms of a vCenter Server managed by SDDC Manager for a workload domain named sfo-w01.

### EXAMPLE 2

```powershell
Request-VcenterAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -filterOut hostOnly
```

This example will return alarms from ESXi hosts of a vCenter Server managed by SDDC Manager for a workload domain named sfo-w01.

### EXAMPLE 3

```powershell
Request-VcenterAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
```

This example will return alarms from vSAN clusters of a vCenter Server managed by SDDC Manager for a workload domain but only for the failed items.

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

### -domain

The name of the workload domain to run against.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -filterOut

Filter out alarms.
One of: hostOnly, vsanOnly.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
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
