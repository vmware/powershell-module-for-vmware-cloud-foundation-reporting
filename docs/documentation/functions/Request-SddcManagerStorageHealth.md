# Request-SddcManagerStorageHealth

## Synopsis

Checks the storage health capacity in an SDDC Manager appliance.

## Syntax

```powershell
Request-SddcManagerStorageHealth [-server] <String> [-user] <String> [-pass] <String> [-localUser] <String> [-localPass] <String> [-failureOnly] [<CommonParameters>]
```

## Description

The `Request-SddcManagerStorageHealth` cmdlet checks the hard disk space in an SDDC Manager appliance.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, -`pass`, `-localUser`, and `-localPass` values:

- Performs checks on the local storage used space in an SDDC Manager appliance and outputs the results.

## Examples

### Example 1

```powershell
Request-SddcManagerStorageHealth -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -localUser [local_username] -localPass [local_password]
```

This example checks the hard disk space in an SDDC Manager appliance.

### Example 2

```powershell
Request-SddcManagerStorageHealth -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -localUser [local_username] -localPass [local_password] -failureOnly
```

This example checks the hard disk space in the SDDC Manager but only reports issues.

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

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable.` For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
