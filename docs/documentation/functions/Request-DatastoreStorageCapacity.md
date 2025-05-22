# Request-DatastoreStorageCapacity

## Synopsis

Checks the datastore usage in all vCenter instances.

## Syntax

```powershell
Request-DatastoreStorageCapacity [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-failureOnly] [<CommonParameters>]
```

## Description

The `Request-DatastoreStorageCapacity` cmdlet checks the datastore usage in all vCenters.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates that network connectivity is available to the SDDC Manager instance.
- Validates that network connectivity is available to the vCenter instance.
- Gathers the details for each vCenter.
- Collects information about datastore usage.

## Examples

### Example 1

```powershell
Request-DatastoreStorageCapacity -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name]
```

This example will check datastores on a vCenter managed by SDDC Manager in a specified workload domain.

### Example 2

```powershell
Request-DatastoreStorageCapacity -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -failureOnly
```

This example will check datastores on a vCenter managed by SDDC Manager in a VMware Cloud Foundation instance in a specified workload domain and will only report issues.

## Parameters

### -server

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

### -user

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

### -pass

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

### -domain

The name of the workload domain to run against.

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
