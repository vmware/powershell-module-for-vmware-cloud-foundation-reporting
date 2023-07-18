# Request-SddcManagerStorageHealth

## Synopsis

Checks the storage health (capacity) in an SDDC Manager appliance.

## Syntax

```powershell
Request-SddcManagerStorageHealth [-server] <String> [-user] <String> [-pass] <String> [-localUser] <String> [-localPass] <String> [-failureOnly] [<CommonParameters>]
```

## Description

The `Request-SddcManagerStorageHealth` cmdlet checks the disk free space on the SDDC Manager appliance.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, -`pass`, `-localUser`, and `-localPass` values:

- Performs checks on the local storage used space and outputs the results

## Examples

### Example 1

```powershell
Request-SddcManagerStorageHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -localUser vcf -localPass VMw@re1!
```

This example checks the hard disk space in the SDDC Manager appliance.

### Example 2

```powershell
Request-SddcManagerStorageHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -localUser vcf -localPass VMw@re1! -failureOnly
```

This example checks the hard disk space in the SDDC Manager appliance and outputs only the failures.

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

### -localUser

The username to authenticate to the SDDC Manager appliance as a local user.

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

### -localPass

The password to authenticate to the SDDC Manager appliance as a local user.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
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
