# Request-NsxtAlert

## Synopsis

Returns alarms from an NSX Manager cluster.

## Syntax

```powershell
Request-NsxtAlert [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-failureOnly] [<CommonParameters>]
```

## Description

The `Request-NsxtAlert` cmdlet returns all alarms from an NSX Manager cluster.
The cmdlet connects to the NSX Manager using the `-server`, `-user`, and `-pass` values:

- Validates that network connectivity is available to the NSX Manager cluster
- Validates that network connectivity is available to the vCenter Server instance
- Gathers the details for the NSX Manager cluster
- Collects the alerts

## Examples

### Example 1

```powershell
Request-NsxtAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
```

This example will return alarms of an NSX Manager cluster managed by SDDC Manager for a workload domain.

### Example 2

```powershell
Request-NsxtAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
```

This example will return alarms of an NSX Manager cluster managed by SDDC Manager for a workload domain but only for the failed items.

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
