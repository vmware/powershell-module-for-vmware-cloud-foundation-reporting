# Request-SddcManagerBackupStatus

## Synopsis

Returns the status of the file-level latest backup task in an SDDC Manager instance.

## Syntax

```powershell
Request-SddcManagerBackupStatus [-server] <String> [-user] <String> [-pass] <String> [-failureOnly] [<CommonParameters>]
```

## Description

The `Request-SddcManagerBackupStatus` cmdlet returns the status of the latest file-level backup task in an SDDC Manager instance.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates network connectivity and authentication to the SDDC Manager instance.
- Collects the latest file-level backup status details.

## Examples

### Example 1

```powershell
Request-SddcManagerBackupStatus -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password]
```

This example will return the status of the latest file-level backup task in an SDDC Manager instance.

### Example 2

```powershell
Request-SddcManagerBackupStatus -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -failureOnly
```

This example will return the status of the latest file-level backup task in an SDDC Manager instance but only reports issues.

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
