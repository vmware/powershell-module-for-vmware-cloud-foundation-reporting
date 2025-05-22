# Publish-SnapshotStatus

## Synopsis

Requests and publishes the snapshot status for the SDDC Manager, vCenter instances, and NSX Edge Nodes managed by SDDC Manager.

## Syntax

### All-WorkloadDomains

```powershell
Publish-SnapshotStatus [-server] <String> [-user] <String> [-pass] <String> [-allDomains] [-failureOnly] [-outputJson <String>] [<CommonParameters>]
```

### Specific-WorkloadDomains

```powershell
Publish-SnapshotStatus [-server] <String> [-user] <String> [-pass] <String> [-workloadDomain] <String> [-failureOnly] [-outputJson <String>] [<CommonParameters>]
```

## Description

The `Publish-SnapshotStatus` cmdlet checks the snapshot status for SDDC Manager, vCenter instances, and NSX Edge Nodes in a VMware Cloud Foundation instance and prepares the data to be published to an HTML report.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates that network connectivity is available to the SDDC Manager instance.
- Performs checks on the snapshot status and outputs the results.

## Examples

### Example 1

```powershell
Publish-SnapshotStatus -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -allDomains
```

This example will publish the snapshot status for the SDDC Manager, vCenter instances, and NSX Edge Nodes managed by SDDC Manager.

### Example 2

```powershell
Publish-SnapshotStatus -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -allDomains -failureOnly
```

This example will publish the snapshot status for the SDDC Manager, vCenter instances, and NSX Edge Nodes managed by SDDC Manager but only reports issues.

### Example 3

```powershell
Publish-SnapshotStatus -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -workloadDomain [workload_domain_name]
```

This example will publish the snapshot status for the SDDC Manager, vCenter instance, and NSX Edge Nodes managed by SDDC Manager for a specified workload domain.

### Example 4

```powershell
Publish-SnapshotStatus -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -allDomains -outputJson [report_path]
```

This example will generate a json for the snapshot status for the SDDC Manager, vCenter instances, and NSX Edge Nodes managed by SDDC Manager
and saves it under the specified report path with filename `<timestamp>-snapshot-status.json`

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
Parameter Sets: Specific-WorkloadDomains
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

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable.` For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

The cmdlet will not publish the snapshot status for NSX Local Manager cluster appliances managed by SDDC Manager.
Snapshots are not recommended for NSX appliances and are disabled by default.

## RELATED LINKS
