# Copy-FiletoSddc

## Synopsis

Copy a file to SDDC Manager.

## Syntax

```powershell
Copy-FiletoSddc [-server] <String> [-user] <String> [-pass] <String> [-vmUser] <String> [-vmPass] <String> [-source] <String> [-destination] <String> [<CommonParameters>]
```

## Description

The `Copy-FiletoSddc` cmdlet copies files to the SDDC Manager appliance.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates that network connectivity is available to the SDDC Manager instance.
- Validates that network connectivity is available to the Management Domain vCenter instance.
- Copies the files to the SDDC Manager appliance.

## Examples

### Example 1

```powershell
Copy-FiletoSddc -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -vmUser [vm_username] -vmPass [vm_password] -source [source_path] -destination [destination_path]
```

This example copies a file to the SDDC Manager appliance.

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

### -source

The source file or folder to copy to the SDDC Manager appliance.

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

### -destination

The destination file or folder to copy to on the SDDC Manager appliance.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 7
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable.` For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
