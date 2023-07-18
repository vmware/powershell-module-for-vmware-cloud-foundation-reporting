# Invoke-VcfConfigReport

## Synopsis

Generates the configuration report.

## Syntax

### All-WorkloadDomains

```powershell
Invoke-VcfConfigReport -sddcManagerFqdn <String> -sddcManagerUser <String> -sddcManagerPass <String> -reportPath <String> [-allDomains] [-darkMode] [<CommonParameters>]
```

### Specific-WorkloadDomain

```powershell
Invoke-VcfConfigReport -sddcManagerFqdn <String> -sddcManagerUser <String> -sddcManagerPass <String> -reportPath <String> -workloadDomain <String> [-darkMode] [<CommonParameters>]
```

## Description

The `Invoke-VcfConfigReport` provides a single cmdlet to generates a configuration report for a VMware Cloud Foundation instance.

## Examples

### Example 1

```powershell
Invoke-VcfConfigReport -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser admin@local -sddcManagerPass VMw@re1!VMw@re1! -reportPath F:\Reporting -allDomains
```

This example generates the configuration report across a VMware Cloud Foundation instance.

### Example 2

```powershell
Invoke-VcfConfigReport -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser admin@local -sddcManagerPass VMw@re1!VMw@re1! -reportPath F:\Reporting -workloadDomain sfo-w01
```

This example generates the configuration report for a specific workload domain within a VMware Cloud Foundation instance.

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

### -allDomains

Switch to run against all workload domains.

```yaml
Type: SwitchParameter
Parameter Sets: All-WorkloadDomains
Aliases:

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -workloadDomain

The name of the workload domain to run against.

```yaml
Type: String
Parameter Sets: Specific-WorkloadDomain
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
