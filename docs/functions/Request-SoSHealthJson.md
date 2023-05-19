# Request-SoSHealthJson

## SYNOPSIS

Run SoS and save the JSON output.

## SYNTAX

### All-WorkloadDomains

```powershell
Request-SoSHealthJson -server <String> -user <String> -pass <String> -reportPath <String> [-allDomains]
 [<CommonParameters>]
```

### Specific-WorkloadDomain

```powershell
Request-SoSHealthJson -server <String> -user <String> -pass <String> -reportPath <String>
 -workloadDomain <String> [<CommonParameters>]
```

## DESCRIPTION

The Request-SoSHealthJson cmdlet connects to SDDC Manager, runs an SoS Health collection to JSON, and saves the
JSON file to the local file system.

## EXAMPLES

### EXAMPLE 1

```powershell
Request-SoSHealthJson -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -reportPath F:\Reporting\HealthReports -allDomains
```

This example runs an SoS Health collection for all domains in the SDDC and saves the JSON output to the local file system.

### EXAMPLE 2

```powershell
Request-SoSHealthJson -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -reportPath F:\Reporting\HealthReports -workloadDomain sfo-w01
```

This example runs an SoS Health collection for a workload domain in the SDDC and saves the JSON output to the local file system.

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

### -reportPath

The path to save the policy report.

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

Switch to run against all workload domains.

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
