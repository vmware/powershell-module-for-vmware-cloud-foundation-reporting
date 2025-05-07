# Publish-NsxtHealthNonSOS

## Synopsis

Publish NSX health only for health checks which are not a part of the SOS Utility NSX health.
Data obtained is a subset of `Publish-NsxtCombinedHealth` cmdlet.

## Syntax

### All-WorkloadDomains

```powershell
Publish-NsxtHealthNonSOS [-server] <String> [-user] <String> [-pass] <String> [-allDomains] [-failureOnly] [-outputJson <String>] [<CommonParameters>]
```

### Specific-WorkloadDomain

```powershell
Publish-NsxtHealthNonSOS [-server] <String> [-user] <String> [-pass] <String> [-workloadDomain] <String> [-failureOnly] [-outputJson <String>] [<CommonParameters>]
```

## Description

The `Publish-NsxtHealthNonSOS` cmdlet performs additional checks outside of the SOS Utility to get the health of NSX on the VMware Cloud Foundation instance and prepares the data to be published to an HTML report.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates that network connectivity and autehentication is available to SDDC Manager.
- Validates that network connectivity and autehentication is available to NSX.
- Performs health checks and outputs the results.

Data obtained is subset of Publish-NsxtCombinedHealth cmdlet.

## Examples

### Example 1

```powershell
Publish-NsxtHealthNonSOS -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -allDomains
```

This example checks NSX health outside the SOS Utility for all workload domains across the VMware Cloud Foundation instance.

### Example 2

```powershell
Publish-NsxtHealthNonSOS -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -workloadDomain [workload_domain_name]
```

This example checks NSX health outside the SOS Utility for a a specified workload domain in a VMware Cloud Foundation instance.

### Example 3

```powershell
Publish-NsxtHealthNonSOS -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -allDomains -failureOnly
```

This example checks NSX health outside the SOS Utility for all workload domains across the VMware Cloud Foundation instance but for only the failed items.


### Example 4

```powershell
Publish-NsxtHealthNonSOS -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -allDomains -outputJson [report_path]
```

This example checks NSX health outside the SOS Utility for all workload domains across the VMware Cloud Foundation instance and
and saves it as JSON under [report_path] with filename `<timestamp>-nsxtcombinedhealthnonsos-status.json`

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

### -outputJson

The path to save the output as a JSON file.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
