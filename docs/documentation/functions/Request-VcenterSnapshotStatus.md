# Request-VcenterSnapshotStatus

## Synopsis

Request the snapshot status for the vCenter Server instance.

## Syntax

```powershell
Request-VcenterSnapshotStatus [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-failureOnly] [<CommonParameters>]
```

## Description

The `Request-VcenterSnapshotStatus` cmdlet checks the snapshot status for vCenter Server instance.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates network connectivity and authentication to the SDDC Manager instance
- Gathers the details for the vCenter Server instance from the SDDC Manager
- Validates network connectivity and authentication to the vCenter Server instance
- Performs checks on the snapshot status and outputs the results

## Examples

### Example 1

```powershell
Request-VcenterSnapshotStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
```

This example will publish the snapshot status for a vCenter Server instance for a specific workload domain.

### Example 2

```powershell
Request-VcenterSnapshotStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
```

This example will publish the snapshot status for a vCenter Server instance for a specific workload domain, but only failed items.

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
