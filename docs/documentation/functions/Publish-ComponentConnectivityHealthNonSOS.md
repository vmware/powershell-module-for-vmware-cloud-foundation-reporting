# Publish-ComponentConnectivityHealthNonSOS

## Synopsis

Request and publish Component Connectivity Health only for health checks which are not a part of SOS Utility NSX health.
Data obtained is a subset of Publish-ComponentConnectivityHealth cmdlet.

## Syntax

### All-WorkloadDomains

```powershell
Publish-ComponentConnectivityHealthNonSOS -server <String> -user <String> -pass <String> [-allDomains] [-failureOnly] [-outputJson <String>] [<CommonParameters>]
```

### Specific-WorkloadDomain

```powershell
Publish-ComponentConnectivityHealthNonSOS -server <String> -user <String> -pass <String> -workloadDomain <String> [-failureOnly] [-outputJson <String>] [<CommonParameters>]
```

## Description

The `Publish-ComponentConnectivityHealthNonSOS` cmdlet checks component connectivity across the VMware Cloud Foundation instance and prepares the data to be published to an HTML report.
The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-pass` values:

- Validates that network connectivity is available to the SDDC Manager instance
- Performs connectivityy health checks and outputs the results

## Examples

### Example 1

```powershell
Publish-ComponentConnectivityHealthNonSOS -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains
```

This example checks the component connectivity outside of SOS utility for all workload domains across the VMware Cloud Foundation instance.

### Example 2

```powershell
Publish-ComponentConnectivityHealthNonSOS -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!  -workloadDomain sfo-w01
```

This example checks the component connectivity outside of SOS utility for a single workload domain in a VMware Cloud Foundation instance.

### Example 3

```powershell
Publish-ComponentConnectivityHealthNonSOS -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -failureOnly
```

This example checks the component connectivity outside of SOS utility for all workload domains across the VMware Cloud Foundation instance but only reports issues.

### Example 4

```powershell
Publish-ComponentConnectivityHealthNonSOS -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -allDomains -jsonOutput F:\Reporting
```

This example checks the component connectivity outside of SOS utility for all workload domains across the VMware Cloud Foundation instance and saves it under F:\Reporting with filename <timestamp>-componentconnectivityhealthnonsos-status.json

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
