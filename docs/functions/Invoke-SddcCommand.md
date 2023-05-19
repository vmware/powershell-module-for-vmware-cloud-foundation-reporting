# Invoke-SddcCommand

## SYNOPSIS

Run a command on SDDC Manager.

## SYNTAX

```powershell
Invoke-SddcCommand [-server] <String> [-user] <String> [-pass] <String> [-vmUser] <String> [-vmPass] <String>
 [-command] <String> [<CommonParameters>]
```

## DESCRIPTION

The Invoke-SddcCommand cmdlet runs a command within the SDDC Manager appliance.
The cmdlet connects to SDDC
Manager using the -server, -user, and -pass values:

- Validates that network connectivity is available to the SDDC Manager instance
- Validates that network connectivity is available to the Management Domain vCenter Server instance
- Runs the command provided within the SDDC Manager appliance

## EXAMPLES

### EXAMPLE 1

```powershell
Invoke-SddcCommand -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -vmUser root -vmPass VMw@re1! -command "chage -l backup"
```

This example runs the command provided on the SDDC Manager appliance as the root user.

### EXAMPLE 2

```powershell
Invoke-SddcCommand -server sfo-vcf01.sfo.rainpole.io -user admin@local -pass VMw@re1!VMw@re1! -vmUser vcf -vmPass VMw@re1! -command "echo Hello World."
```

This example runs the command provided on the SDDC Manager appliance as the vcf user.

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

### -vmUser

The username to authenticate to the virtual machine.

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

### -vmPass

The password to authenticate to the virtual machine.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -command

The command to run on the virtual machine.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 6
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
