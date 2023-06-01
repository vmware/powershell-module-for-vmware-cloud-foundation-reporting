# Request-NsxtTier0BgpStatus

## SYNOPSIS

Returns the BGP status for all Tier-0 gateways managed by the NSX Local Manager cluster.

## SYNTAX

```powershell
Request-NsxtTier0BgpStatus [-server] <String> [-user] <String> [-pass] <String> [-domain] <String>
 [-failureOnly] [<CommonParameters>]
```

## DESCRIPTION

The Request-NsxtTier0BgpStatus cmdlet returns the BGP status for all Tier-0 gateways managed by the NSX Manager
cluster.
The cmdlet connects to the NSX Local Manager using the -server, -user, and -pass values:

- Validates that network connectivity is available to the SDDC Manager instance
- Validates that network connectivity is available to the NSX Local Manager cluster
- Gathers the details for the NSX Local Manager cluster
- Collects the BGP status for all Tier-0s managed by the NSX Local Manager cluster

## EXAMPLES

### EXAMPLE 1

```powershell
Request-NsxtTier0BgpStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01
```

This example will return the BGP status for all Tier-0 gateways managed by the NSX Local Manager cluster that is managed by SDDC Manager for a workload domain.

### EXAMPLE 2

```powershell
Request-NsxtTier0BgpStatus -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-w01 -failureOnly
```

This example will return the BGP status for all Tier-0 gateways managed by the NSX Local Manager cluster that is managed by SDDC Manager for a workload domain but only reports issues.

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

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
