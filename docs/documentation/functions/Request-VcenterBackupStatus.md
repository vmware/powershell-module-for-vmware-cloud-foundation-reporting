# Request-VcenterBackupStatus

## SYNOPSIS

Returns the status of the file-level latest backup of a vCenter Server instance.

## SYNTAX

```powershell
Request-VcenterBackupStatus [-server] <String> [-user] <String> [-pass] <String> [-domain] <String>
 [-failureOnly] [<CommonParameters>]
```

## DESCRIPTION

The Request-VcenterBackupStatus cmdlet returns the status of the latest backup of a vCenter Server instance.
The cmdlet connects to the SDDC Manager using the -server, -user, and -pass values:

- Validates network connectivity and authentication to the SDDC Manager instance
- Gathers the details for the NvCenter Server instance from the SDDC Manager
- Validates network connectivity and authentication to the vCenter Server instance
- Collects the file-level backup status details

## EXAMPLES

### EXAMPLE 1

```powershell
Request-VcenterBackupStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
```

This example will return the status of the latest file-level backup of a vCenter Server instance managed by SDDC Manager for a workload domain.

### EXAMPLE 2

```powershell
Request-VcenterBackupStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
```

This example will return the status of the latest file-level backup of a vCenter Server instance managed by SDDC Manager for a workload domain but only reports issues.

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
