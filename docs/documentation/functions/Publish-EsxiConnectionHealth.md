# Publish-EsxiConnectionHealth

## Synopsis

Publish the connection status of ESXi hosts in a workload domain in HTML format.

## Syntax

### All-WorkloadDomains

```powershell
Publish-EsxiConnectionHealth -server <String> -user <String> -pass <String> [-allDomains] [-failureOnly] [<CommonParameters>]
```

### Specific-WorkloadDomain

```powershell
Publish-EsxiConnectionHealth -server <String> -user <String> -pass <String> -workloadDomain <String> [-failureOnly] [<CommonParameters>]
```

## Description

The `Publish-EsxiConnectionHealth` cmdlet returns the status of virtual machines with connected CD-ROMS in a workload domain in HTML format.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates that network connectivity is available to the vCenter Server instance
- Validates the authentication to vCenter Server with credentials from SDDC Manager
- Publishes information

## Examples

### Example 1

```powershell
Publish-EsxiConnectionHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
```

This example will publish the connection status of ESXi hosts in all workload domains.

### Example 2

```powershell
Publish-EsxiConnectionHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
```

This example will publish the connection status of ESXi hosts in a workload domain.

### Example 3

```powershell
Publish-EsxiConnectionHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -failureOnly
```

This example will publish the connection status of ESXi hosts in all workload domains but only for failures.

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

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
