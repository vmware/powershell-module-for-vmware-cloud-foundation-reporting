# Request-DatastoreStorageCapacity

## SYNOPSIS

Checks the datastore usage in all vCenter Server instances.

## SYNTAX

```powershell
Request-DatastoreStorageCapacity [-server] <String> [-user] <String> [-pass] <String> [-domain] <String>
 [-failureOnly] [<CommonParameters>]
```

## DESCRIPTION

The Request-DatastoreStorageCapacity cmdlet checks the datastore usage in all vCenters.
The cmdlet
connects to SDDC Manager using the -server, -user, and -pass values:

- Validates that network connectivity is available to the SDDC Manager instance
- Validates that network connectivity is available to the vCenter Server instance
- Gathers the details for each vCenter Server
- Collects information about datastore usage

## EXAMPLES

### EXAMPLE 1

```powershell
Request-DatastoreStorageCapacity -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
```

This example will check datastores on all vCenter Servers managed by SDDC Manager in a VMware Cloud Foundation instance but only failed items.

### EXAMPLE 2

```powershell
Request-DatastoreStorageCapacity -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
```

This example will check datastore on a vCenter Servers managed by SDDC Manager for a workload domain.

## PARAMETERS

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
