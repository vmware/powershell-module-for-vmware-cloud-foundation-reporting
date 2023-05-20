# Publish-NsxtHealthNonSOS

## SYNOPSIS

Publish NSX Manager Health only for health checks which are not a part of SOS Utility NSX health.
Data obtained is a subset of Publish-NsxtCombinedHealth cmdlet.

## SYNTAX

### All-WorkloadDomains

```powershell
Publish-NsxtHealthNonSOS -server <String> -user <String> -pass <String> [-allDomains] [-failureOnly]
 [-outputJson <String>] [<CommonParameters>]
```

### Specific-WorkloadDomain

```powershell
Publish-NsxtHealthNonSOS -server <String> -user <String> -pass <String> -workloadDomain <String> [-failureOnly]
 [-outputJson <String>] [<CommonParameters>]
```

## DESCRIPTION

The Publish-NsxtHealthNonSOS cmdlet performs additional checks outside of SOS Utility to get the health of NSX Manager on the VMware Cloud Foundation instance
and prepares the data to be published to an HTML report.
Data obtained is subset of Publish-NsxtCombinedHealth cmdlet.
The cmdlet connects to SDDC Manager using the
-server, -user, and password values:

- Validates that network connectivity and autehentication is available to SDDC Manager
- Validates that network connectivity and autehentication is available to NSX Manager
- Performs health checks and outputs the results

## EXAMPLES

### EXAMPLE 1

```powershell
Publish-NsxtHealthNonSOS -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
```

This example checks NSX Manager health outside SOS Utility for all workload domains across the VMware Cloud Foundation instance.

### EXAMPLE 2

```powershell
Publish-NsxtHealthNonSOS -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -workloadDomain sfo-w01
```

This example checks NSX Manager health outside SOS Utility for a single workload domain in a VMware Cloud Foundation instance.

### EXAMPLE 3

```powershell
Publish-NsxtHealthNonSOS -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -failureOnly
```

This example checks NSX Manager health outside SOS Utility for all workload domains across the VMware Cloud Foundation instance but only reports issues.
```

### EXAMPLE 4

```powershell
Publish-NsxtHealthNonSOS -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -outputJson F:\Reporting
```

This example checks NSX Manager health outside SOS Utility for all workload domains across the VMware Cloud Foundation instance and
and saves it as JSON under F:\Reporting with filename <timestamp>-nsxtcombinedhealthnonsos-status.json

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
