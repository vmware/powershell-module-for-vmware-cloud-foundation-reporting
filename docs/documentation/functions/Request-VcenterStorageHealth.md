# Request-VcenterStorageHealth

## SYNOPSIS

Checks the disk usage on a vCenter Server instance.

## SYNTAX

```powershell
Request-VcenterStorageHealth [-server] <String> [-user] <String> [-pass] <String> [-domain] <String>
 [-failureOnly] [<CommonParameters>]
```

## DESCRIPTION

The Request-VcenterStorageHealth cmdlets checks the disk space usage on a vCenter Server.
The cmdlet
connects to SDDC Manager using the -server, -user, and -pass values:

- Validates network connectivity and authentication to the SDDC Manager instance
- Validates network connectivity and authentication to the vCenter Server instance
- Collects information for the disk usage
- Checks disk usage against thresholds and outputs the results

## EXAMPLES

### EXAMPLE 1

```powershell
Request-VcenterStorageHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
```

This example will check disk usage for a single workload domain

### EXAMPLE 2

```powershell
Request-VcenterStorageHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -failureOnly
```

This example will check the disk usage for all vCenter Server instances but only reports issues.

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
