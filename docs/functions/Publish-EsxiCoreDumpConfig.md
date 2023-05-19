# Publish-EsxiCoreDumpConfig

## SYNOPSIS

Generates an ESXi core dump configuration report.

## SYNTAX

### All-WorkloadDomains

```powershell
Publish-EsxiCoreDumpConfig -server <String> -user <String> -pass <String> [-html] [-allDomains]
 [<CommonParameters>]
```

### Specific--WorkloadDomain

```powershell
Publish-EsxiCoreDumpConfig -server <String> -user <String> -pass <String> [-html] -workloadDomain <String>
 [<CommonParameters>]
```

## DESCRIPTION

The Publish-EsxiCoreDumpConfig cmdlet generates an ESXi core dump report for a workload domain.
The cmdlet
connects to SDDC Manager using the -server, -user, and -pass values:

- Validates that network connectivity is available to the SDDC Manager instance
- Validates that network connectivity is available to the vCenter Server instance
- Generates an ESXi core dump report for all ESXi hosts in a workload domain

## EXAMPLES

### EXAMPLE 1

```powershell
Publish-EsxiCoreDumpConfig -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -alldomains
```

This example generates an ESXi core dump report for all ESXi hosts across the VMware Cloud Foundation instance.

## PARAMETERS

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

### -html

Switch to output the report in HTML format.

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
Parameter Sets: Specific--WorkloadDomain
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
