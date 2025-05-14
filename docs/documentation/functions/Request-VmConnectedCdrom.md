# Request-VmConnectedCdrom

## Synopsis

Returns the status of virtual machines with connected CD-ROMs in a specified workload domain.

## Syntax

```powershell
Request-VmConnectedCdrom [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [<CommonParameters>]
```

## Description

The `Request-VmConnectedCdrom` cmdlet returns the status of virtual machines with connected CD-ROMs in a specified workload domain.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates that network connectivity is available to the SDDC Manager instance.
- Validates that network connectivity is available to the vCenter instance.
- Gathers the status of virtual machines with connected CD-ROMs in a specified workload domain.

## Examples

### Example 1

```powershell
Request-VmConnectedCdrom -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name]
```

This example returns the status of virtual machines with connected CD-ROMs in a specified workload domain.

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

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
