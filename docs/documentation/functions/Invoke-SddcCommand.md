# Invoke-SddcCommand

## Synopsis

Run a command on SDDC Manager.

## Syntax

```powershell
Invoke-SddcCommand [-server] <String> [-user] <String> [-pass] <String> [-vmUser] <String> [-vmPass] <String> [-command] <String>
[<CommonParameters>]
```

## Description

The `Invoke-SddcCommand` cmdlet runs a command within the SDDC Manager appliance.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates that network connectivity is available to the SDDC Manager instance
- Validates that network connectivity is available to the Management Domain vCenter Server instance
- Runs the command provided within the SDDC Manager appliance

## Examples

### Example 1

```powershell
Invoke-SddcCommand -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -vmUser [local_username] -vmPass [local_password] -command "chage -l backup"
```

This example runs the command provided on the SDDC Manager appliance with the user specified for the `-vmUser` parameter.

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

### -vmUser

The username to authenticate to the virtual machine.

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

### -vmPass

The password to authenticate to the virtual machine.

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

### -command

The command to run on the virtual machine.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
