# Publish-StorageCapacityHealth

## SYNOPSIS

Request and publish the storage capacity status.

## SYNTAX

### All-WorkloadDomains

```powershell
Publish-StorageCapacityHealth -server <String> -user <String> -pass <String> -localUser <String>
 -localPass <String> [-allDomains] [-failureOnly] [-outputJson <String>] [<CommonParameters>]
```

### Specific-WorkloadDomain

```powershell
Publish-StorageCapacityHealth -server <String> -user <String> -pass <String> -localUser <String>
 -localPass <String> -workloadDomain <String> [-failureOnly] [-outputJson <String>] [<CommonParameters>]
```

## DESCRIPTION

The Publish-StorageCapacityHealth cmdlet checks the storage usage status for SDDC Manager, vCenter Server,
Datastores and ESXi hosts, in a VMware Cloud Foundation instance and prepares the data to be published
to an HTML report or plain text to console.
The cmdlet connects to SDDC Manager using the -server, -user, -pass, -localUser, and -localPass values:

- Validates the network connectivity and authantication to the SDDC Manager instance
- Performs checks on the storage usage status and outputs the results

## EXAMPLES

### EXAMPLE 1

```powershell
Publish-StorageCapacityHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -localUser vcf -localPass VMw@re1! -allDomains
```

This example will publish storage usage status for SDDC Manager, vCenter Server instances, ESXi hosts, and datastores in a VMware Cloud Foundation instance

### EXAMPLE 2

```powershell
Publish-StorageCapacityHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -localUser vcf -localPass VMw@re1! -allDomains -failureOnly
```

This example will publish storage usage status for SDDC Manager, vCenter Server instances, ESXi hosts, and datastores in a VMware Cloud Foundation instance but only for the failed items.

### EXAMPLE 3

```powershell
Publish-StorageCapacityHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -localUser vcf -localPass VMw@re1! -workloadDomain sfo-w01
```

This example will publish storage usage status for a specific workload domain in a VMware Cloud Foundation instance
```

### EXAMPLE 4

```powershell
Publish-StorageCapacityHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -localUser vcf -localPass VMw@re1! -workloadDomain sfo-w01 -outputJson F:\Reporting
```

This example will publish storage usage status for a specific workload domain in a VMware Cloud Foundation instance
and saves it as JSON under F:\Reporting with filename <timestamp>-storagecapacityhealth-status.json

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

### -localUser

The username to authenticate to the SDDC Manager appliance as a local user.

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

### -localPass

The password to authenticate to the SDDC Manager appliance as a local user.

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
