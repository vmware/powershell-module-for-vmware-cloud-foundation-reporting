# Publish-ComponentConnectivityHealth

## Synopsis

Request and publish component connectivity health.

## Syntax

### All-WorkloadDomains

```powershell
Publish-ComponentConnectivityHealth [-server] <String> [-user] <String> [-pass] <String> [-json] <String> [-allDomains] [-failureOnly] [<CommonParameters>]
```

### Specific-WorkloadDomain

```powershell
Publish-ComponentConnectivityHealth [-server] <String> [-user] <String> [-pass] <String> [-json] <String> [-workloadDomain] <String> [-failureOnly] [<CommonParameters>]
```

## Description

The `Publish-ComponentConnectivityHealth` cmdlet checks component connectivity across the VMware Cloud Foundation instance and prepares the data to be published to an HTML report.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates that network connectivity is available to the SDDC Manager instance.
- Performs connectivity health checks and outputs the results.

## Examples

### Example 1

```powershell
Publish-ComponentConnectivityHealth -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -json [json-file] -allDomains
```

This example checks the component connectivity for all workload domains across the VMware Cloud Foundation instance.

### Example 2

```powershell
Publish-ComponentConnectivityHealth -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -json [json-file] -workloadDomain [workload_domain_name]
```

This example checks the component connectivity for a specified workload domain in a VMware Cloud Foundation instance.

### Example 3

```powershell
Publish-ComponentConnectivityHealth -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -json [json-file] -allDomains -failureOnly
```

This example checks the component connectivity for all workload domains across the VMware Cloud Foundation instance but only reports issues.

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

### -json

The full path to the JSON file to output the results to.

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

Switch to run health checks across all workload domains.

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
