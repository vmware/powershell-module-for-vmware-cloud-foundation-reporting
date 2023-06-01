# Request-VirtualNetwork

## SYNOPSIS

Gets vSphere virtual networking configuration from a vCenter Server instance.

## SYNTAX

```powershell
Request-VirtualNetwork [-server] <String> [-user] <String> [-pass] <String> [-domain] <String>
 [<CommonParameters>]
```

## DESCRIPTION

The Request-VirtualNetwork cmdlets gets vSphere virtual networking configuration for a vCenter Server instance.
The cmdlet connects to SDDC Manager using the -server, -user, and -pass values:

- Validates that network connectivity is available to the SDDC Manager instance
- Validates that network connectivity is available to the vCenter Server instance
- Gathers the vSphere virtual networking configuration from vCenter Server

## EXAMPLES

### EXAMPLE 1

```powershell
Request-VirtualNetwork -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -domain sfo-m01
```

This example gets the vSphere virtual networking configurationfor a vCenter Server instance based on the workload domain provided.

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

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
