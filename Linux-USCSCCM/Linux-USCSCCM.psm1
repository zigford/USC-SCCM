function Get-WmiObject {
    [cmdletbinding()]
    Param(
        $ClassName,$Namespace,$Query,
        [Parameter(Mandatory=$true)]$ComputerName,$UserName,$Password
    )

    begin{
        if ($Query -and $ClassName) {
            Write-Error "Query and ClassName parameters are mutually exclusive"
            throw;
        }
        if ($ClassName) {
            $Query = "select * from $ClassName"
        } 
        if (-Not $Query) {
            Write-Error "You must specify a query or a classname"
            throw;
        }
        if (-Not $Namespace) {
            $Namespace = '//./root/cimv2'
        } else {
            $Namespace = "//./$($Namespace.replace('\','/'))"
        }
        if ($UserName -match '\\') {
            $UserName = $UserName.replace('\','/')
        }
        if (-Not $UserName -and $Global:CfgUserName) {
            $UserName = $Global:CfgUsername
        }
        if (-Not $Password -and $Global:CfgPassword) {
            $Password = $Global:CfgPassword
        }
        if (-Not $Domain -and $Global:CfgDomain) {
            $Domain = $Global:CfgDomain
        }
    }
    process{
        $wmibin = '/bin/wmic'
        $wmiargs = "--user '$Domain/$UserName%$Password' --namespace=$Namespace //$ComputerName ""$Query"""
        Write-Debug "executing wmic with args: $wmiargs"
        #$Out = Start-Process -FilePath $wmibin -ArgumentList $wmiargs 
        $i = 0
        Invoke-Expression "$wmibin $wmiargs" | ForEach-Object {
            $obj = $_
            Switch ($i) {
                0 {
                    $Class = $obj.split()[-1]
                }
                1 {
                    $HTNames = $obj.split('|')
                }
                Default {
                    $PSObject = New-Object -TypeName PSObject
                    $values = $obj.split('|')
                    for ($a=0; $a -lt $values.count; $a++) {
                        Write-Debug "Adding Name: $($HTNames[$a]) with value: $($values[$a])"
                        $PSObject | Add-Member -MemberType NoteProperty -Name $HTNames[$a] -Value $values[$a]
                    } 
                    $PSObject
                }
            }
            $i++
        }
    }
    end{
    }
}

function Test-Connection {
    ##############################
    #.SYNOPSIS
    #Re-implement test-connection on unix
    #
    #.DESCRIPTION
    #Use binary pint to emulate test-connection used in many windows centric scripts
    #
    #.PARAMETER Count
    #Specify the amount of pings to performs
    #
    #.PARAMETER Quiet
    #Specify to only output true or false
    #
    #.PARAMETER ComputerName
    #Specify the computer hostname to attempt connection to
    #
    #.EXAMPLE
    #Test-Connection -ComputerName jessepi -Count 1 -Quiert
    #
    #.NOTES
    #General notes
    ##############################
    [CmdLetBinding()]
    Param(
        [Parameter(Mandatory=$true)]$ComputerName,
        [int]$Count=3,[switch]$Quiet,
        [int]$TTL=60 
    )
    Begin{
        $pingcmd = (Get-Command ping).Path
        if (-Not (Test-Path -Path $pingcmd)) {
            Write-Error "Cannot find ping. Might have to install with apt-get"
        }
    }
    Process{
        $builtcommand = "-c $Count -t $TTL $ComputerName"
        $pingOutput = & "/bin/ping" -c $Count -t $TTL $ComputerName
        If ($Quiet) {
            $?    
        } else {
            $pingOutput
        }    
    }
}