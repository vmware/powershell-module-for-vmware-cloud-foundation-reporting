# Publish-NsxtAlert

## SYNOPSIS

Publish system alerts/alarms from a NSX Manager cluster managed by SDDC Manager.

## SYNTAX

### All-WorkloadDomains

```powershell
Publish-NsxtAlert -server <String> -user <String> -pass <String> [-allDomains] [-failureOnly]
 [<CommonParameters>]
```

### Specific-WorkloadDomain

```powershell
Publish-NsxtAlert -server <String> -user <String> -pass <String> -workloadDomain <String> [-failureOnly]
 [<CommonParameters>]
```

## DESCRIPTION

The Publish-NsxtAlert cmdlet returns all alarms from an NSX Manager cluster.
The cmdlet connects to the NSX Manager using the -server, -user, and -pass values:

- Validates that network connectivity is available to the NSX Manager cluster
- Validates that network connectivity is available to the vCenter Server instance
- Gathers the details for the NSX Manager cluster
- Collects the alerts

## EXAMPLES

### EXAMPLE 1

```powershell
Publish-NsxtAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
```

This example will return alarms from all NSX Manager clusters managed by SDDC Manager for a all workload domains.

### EXAMPLE 2

```powershell
Publish-NsxtAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -failureOnly
```

This example will return alarms from all NSX Manager clusters managed by SDDC Manager for a all workload domains but only for the failed items.

### EXAMPLE 3

```powershell
Publish-NsxtAlert -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
```

This example will return alarms from the NSX Manager cluster managed by SDDC Manager for a workload domain named sfo-w01.

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
