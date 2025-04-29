# Invoke-VcfUpgradePrecheck

## Synopsis

Perform upgrade precheck.

## Syntax

```powershell
Invoke-VcfUpgradePrecheck -sddcManagerFqdn <String> -sddcManagerUser <String> -sddcManagerPass <String> -reportPath <String> -workloadDomain <String> [-darkMode] [<CommonParameters>]
```

## Description

The `Invoke-VcfUpgradePrecheck` runs an upgrade precheck for a workload domain

## Examples

### Example 1

```powershell
Invoke-VcfUpgradePrecheck -sddcManagerFqdn [sddc_manager_fqdn] -sddcManagerUser [admin_username] -sddcManagerPass [admin_password] -reportPath [report_path] -workloadDomain [workload_domain_name]
```

This example runs a health check for a specific workload domain within an SDDC Manager instance.

## Parameters

### -sddcManagerFqdn

The fully qualified domain name of the SDDC Manager.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
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
Position: Named
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
Position: Named
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
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -workloadDomain

The name of the workload domain to run against.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
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

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
