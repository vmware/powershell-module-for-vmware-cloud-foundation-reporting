# Invoke-VcfOverviewReport

## Synopsis

Generates the system overview report for a VMware Cloud Foundation instance.

## Syntax

```powershell
Invoke-VcfOverviewReport [-sddcManagerFqdn] <String> [-sddcManagerUser] <String> [-sddcManagerPass] <String> [-reportPath] <String> [-darkMode] [-anonymized] [<CommonParameters>]
```

## Description

The `Invoke-VcfOverviewReport` provides a single cmdlet to generates a system overview report for a VMware Cloud Foundation instance.

## Examples

### Example 1

```powershell
Invoke-VcfOverviewReport -sddcManagerFqdn [sddc_manager_fqdn] -sddcManagerUser [admin_username] -sddcManagerPass [admin_password] -reportPath [report_path]
```

This example generates the system overview report for a VMware Cloud Foundation instance.

### Example 2

```powershell
Invoke-VcfOverviewReport -sddcManagerFqdn [sddc_manager_fqdn] -sddcManagerUser [admin_username] -sddcManagerPass [admin_password] -reportPath [report_path] -anonymized
```

This example generates the system overview report for a VMware Cloud Foundation instance, but will anonymize the output.

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

### -reportPath

The path to save the policy report.

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

### -darkMode

Switch to enable dark mode for the report.

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

### -anonymized

Switch to enable anonymized output for the report.

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
