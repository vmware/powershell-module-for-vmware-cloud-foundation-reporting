# Request-SoSHealthJson

## Synopsis

Run SoS and save the JSON output.

## Syntax

### All-WorkloadDomains

```powershell
Request-SoSHealthJson [-server] <String> [-user] <String> [-pass] <String> [-reportPath] <String> [-allDomains] [<CommonParameters>]
```

### Specific-WorkloadDomain

```powershell
Request-SoSHealthJson [-server] <String> [-user] <String> [-pass] <String> [-reportPath] <String> [-workloadDomain] <String> [<CommonParameters>]
```

## Description

The `Request-SoSHealthJson` cmdlet connects to SDDC Manager, runs an SoS health collection and saves to a JSON file on the local file system.

## Examples

### Example 1

```powershell
Request-SoSHealthJson -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -reportPath [report_path] -allDomains
```

This example runs an SoS health collection for all domains in the SDDC and saves the JSON file on the local file system in the specified report path.

### Example 2

```powershell
Request-SoSHealthJson -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -reportPath [report_path] -workloadDomain [workload_domain_name]
```

This example runs an SoS health collection for a specified workload domain in the SDDC and saves the JSON file on the local file system in the specified report path.

## Parameters

### -server

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

### -user

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

### -pass

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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable.` For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
