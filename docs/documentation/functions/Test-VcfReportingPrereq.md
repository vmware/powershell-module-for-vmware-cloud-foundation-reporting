# Test-VcfReportingPrereq

## Synopsis

Verifies that the minimum dependencies are met to run the PowerShell module.

## Syntax

```powershell
Test-VcfReportingPrereq [-sddcManagerFqdn] <String> [-sddcManagerUser] <String> [-sddcManagerPass] <String> [<CommonParameters>]
```

## Description

The `Test-VcfReportingPrereq` cmdlet checks that all the prerequisites have been met to run the PowerShell module.

## Examples

### Example 1

```powershell
Test-VcfReportingPrereq -sddcManagerFqdn [sddc_manager_fqdn] -sddcManagerUser [admin_username] -sddcManagerPass [admin_password]
```

This example runs the prerequisite validation.

## Parameters

### -sddcManagerFqdn

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

### -sddcManagerUser

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

### -sddcManagerPass

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

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
