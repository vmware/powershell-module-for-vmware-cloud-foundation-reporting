# Publish-NsxtTransportNodeTunnelStatus

## Synopsis

Request and publish the status of NSX transport node tunnels.

## Syntax

### All-WorkloadDomains

```powershell
Publish-NsxtTransportNodeTunnelStatus [-server] <String> [-user] <String> [-pass] <String> [-allDomains] [-failureOnly] [-outputJson <String>] [<CommonParameters>]
```

### Specific-WorkloadDomain

```powershell
Publish-NsxtTransportNodeTunnelStatus [-server] <String> [-user] <String> [-pass] <String> [-workloadDomain] <String> [-failureOnly] [-outputJson <String>] [<CommonParameters>]
```

## Description

The `Publish-NsxtTransportNodeStatus` cmdlet checks the status NSX transport node tunnels and prepares the data to be published to an HTML report.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates that network connectivity is available to the SDDC Manager instance.
- Performs checks on the NSX transport node tunnel status and outputs the results.

## Examples

### Example 1

```powershell
Publish-NsxtTransportNodeTunnelStatus -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -allDomains
```

This example will publish the status of all the NSX transport node tunnels in a VMware Cloud Foundation instance.

### Example 2

```powershell
Publish-NsxtTransportNodeTunnelStatus -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -allDomains -failureOnly
```

This example will publish thestatus of all the NSX transport node tunnels in a VMware Cloud Foundation instance but only reports issues.

### Example 3

```powershell
Publish-NsxtTransportNodeTunnelStatus -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -workloadDomain [workload_domain_name]
```

This example will publish the BGP status for the NSX transport node tunnels in a VMware Cloud Foundation instance for a specified workload domain.

### Example 4

```powershell
Publish-NsxtTransportNodeTunnelStatus -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -allDomains -outputJson [report_path]
```

This example will generate a JSON for the status of all of the NSX transport node tunnels in a VMware Cloud Foundation instance and saves it under the specified report path with filename `<timestamp>-nsxttntunnel-status.json`

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
