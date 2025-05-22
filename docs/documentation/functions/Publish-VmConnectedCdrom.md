# Publish-VmConnectedCdrom

## Synopsis

Publish the status of virtual machines with connected CD-ROMs in a workload domain in HTML format.

## Syntax

### All-WorkloadDomains

```powershell
Publish-VmConnectedCdrom [-server] <String> [-user] <String> [-pass] <String> [-allDomains] [-outputJson <String>]  [<CommonParameters>]
```

### Specific-WorkloadDomain

```powershell
Publish-VmConnectedCdrom [-server] <String> [-user] <String> [-pass] <String> [-workloadDomain] <String> [-outputJson <String>]  [<CommonParameters>]
```

## Description

The `Publish-VmConnectedCdrom` cmdlet returns the status of virtual machines with connected CD-ROMS in a workload domain in HTML format.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates that network connectivity is available to the vCenter instance.
- Validates the authentication to vCenter with credentials from SDDC Manager.
- Publishes information.

## Examples

### Example 1

```powershell
Publish-VmConnectedCdrom -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -allDomains
```

This example will return the status of virtual machines with connected CD-ROMs in all workload domains.

### Example 2

```powershell
Publish-VmConnectedCdrom -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -workloadDomain [workload_domain_name]
```

This example will return the status of virtual machines with connected CD-ROMs a specified workload domain.

### Example 3

```powershell
Publish-VmConnectedCdrom -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -allDomains -outputJson [report_path]
```

This example will generate a json with the status of virtual machines with connected CD-ROMs in all workload domains
and saves it under the specified report path with filename `<timestamp>-cdrom-status.json`

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
