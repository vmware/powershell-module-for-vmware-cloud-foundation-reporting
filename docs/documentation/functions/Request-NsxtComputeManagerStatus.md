# Request-NsxtComputeManagerStatus

## Synopsis

Returns the status of the compute managers attached to NSX.

## Syntax

```powershell
Request-NsxtComputeManagerStatus [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-failureOnly] [<CommonParameters>]
```

## Description

The `Request-NsxtComputeManagerStatus` cmdlet returns the status of the compute managers attached to NSX.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates network connectivity and authentication to the SDDC Manager instance.
- Gathers the details for NSX from the SDDC Manager.
- Validates network connectivity and authentication to NSX.
- Collects the status of the compute managers.

## Examples

### Example 1

```powershell
Request-NsxtComputeManagerStatus -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name]
```

This example will return the status of the compute managers attached to NSX managed by SDDC Manager for a specified workload domain.

### Example 2

```powershell
Request-NsxtComputeManagerStatus -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -failureOnly
```

This example will return the status of the compute managers attached to NSX managed by SDDC Manager for a specified workload domain but only reports issues.

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
