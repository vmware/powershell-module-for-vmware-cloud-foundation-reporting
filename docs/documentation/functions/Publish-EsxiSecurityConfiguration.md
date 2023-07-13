# Publish-EsxiSecurityConfiguration

## SYNOPSIS

Publish ESXi security information in HTML format.

## SYNTAX

### All-WorkloadDomains

```powershell
Publish-EsxiSecurityConfiguration -server <String> -user <String> -pass <String> [-allDomains]
 [<CommonParameters>]
```

### Specific-WorkloadDomain

```powershell
Publish-EsxiSecurityConfiguration -server <String> -user <String> -pass <String> -workloadDomain <String>
 [<CommonParameters>]
```

## DESCRIPTION

The Publish-EsxiSecurityConfiguration cmdlet returns ESXi security information in HTML format.
The cmdlet connects to the SDDC Manager using the -server, -user, and -pass values:

- Validates that network connectivity is available to the vCenter Server instance
- Validates the authentication to vCenter Server with credentials from SDDC Manager
- Publishes information

## EXAMPLES

### EXAMPLE 1

```powershell
Publish-EsxiSecurityConfiguration -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
```

This example will return ESXi security details from all clusters in vCenter Server managed by SDDC Manager for a all workload domains.

### EXAMPLE 2

```powershell
Publish-EsxiSecurityConfiguration -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
```

This example will return ESXi security details from all clusters in vCenter Server managed by SDDC Manager for a workload domain named sfo-w01.

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

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).