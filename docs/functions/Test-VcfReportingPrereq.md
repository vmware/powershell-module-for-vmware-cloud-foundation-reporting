# Test-VcfReportingPrereq

## SYNOPSIS

Validate prerequisites to run the PowerShell module.

## SYNTAX

```powershell
Test-VcfReportingPrereq [-sddcManagerFqdn] <String> [-sddcManagerUser] <String> [-sddcManagerPass] <String>
 [<CommonParameters>]
```

## DESCRIPTION

The Test-VcfReportingPrereq cmdlet checks that all the prerequisites have been met to run the PowerShell module.

## EXAMPLES

### EXAMPLE 1

```powershell
Test-VcfReportingPrereq -sddcManagerFqdn sfo-vcf01.sfo.rainpole.io -sddcManagerUser admin@local -sddcManagerPass VMw@re1!VMw@re1!
```

This example runs the prerequisite validation.

## PARAMETERS

### -sddcManagerFqdn

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

### -sddcManagerUser

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

### -sddcManagerPass

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
