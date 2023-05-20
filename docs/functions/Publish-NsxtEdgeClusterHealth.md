# Publish-NsxtEdgeClusterHealth

## SYNOPSIS

Formats the NSX Edge Cluster Health data from the SoS JSON output.

## SYNTAX

```powershell
Publish-NsxtEdgeClusterHealth [-json] <String> [-html] [-failureOnly] [<CommonParameters>]
```

## DESCRIPTION

The Publish-NsxtEdgeClusterHealth cmdlet formats the NSX Edge Cluster Health data from the SoS JSON output and
publishes it as either a standard PowerShell object or an HTML object.

## EXAMPLES

### EXAMPLE 1

```powershell
Publish-NsxtEdgeClusterHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1!
```

This example extracts and formats the NSX Edge Cluster Health data as a PowerShell object from the JSON file.

### EXAMPLE 2

```powershell
Publish-NsxtEdgeClusterHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -html
```

This example extracts and formats the NSX Edge Cluster Health data as an HTML object from the JSON file.

### EXAMPLE 3

```powershell
Publish-NsxtEdgeClusterHealth -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -failureOnly
```

This example extracts and formats the NSX Edge Cluster Health data as a PowerShell object from the JSON file for only the failed items.

## PARAMETERS

### -json

The path to the JSON file containing the SoS Health Summary data.

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

### -html

Specifies that the output should be formatted as an HTML object.

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

### -failureOnly

Specifies that the output should only contain failed items.

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
