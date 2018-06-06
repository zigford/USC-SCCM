<#v1.5 
	(Modified Send-CfgMachinePolicyUpdate to wait 2 seconds rather than 10 between downloading
	and evaluating policy)
	(Modified Send-WOL to send the WOL packet to port 1230 and port 9)
	(Modified Get-CfgClientInventory default properties)
	(Added new Install-CCM command)
    (Added Admin test to Send-Wol)
	#>
#v1.4 (Added documentation)
#v1.3 (Added Send-RepairCCM)

function Import-CfgGlobalVars {
[CmdLetBinding()]
Param()
    $VarFile = "$env:LOCALAPPDATA\USC-SCCM\Vars.xml"
    #Try import SCCM SiteCode and SiteServer
    If (Test-Path $VarFile) {
        Import-Clixml -Path $VarFile | %{ Set-Variable $_.Name $_.Value -Scope Global }
    
    }
    If ($cfgSiteServer) { $connectionTestSuccess = Test-connection -ComputerName $cfgSiteServer -Count 1 -Quiet }
    while ($connectionTestSuccess -ne $True -or (-Not $cfgSiteServer)) {
        $Global:CfgSiteServer = Read-Host -Prompt "Enter your site server hostname: "
        $connectionTestSuccess = Test-connection -ComputerName $cfgSiteServer -Count 1 -Quiet 
    }

    If ($CfgSiteCode -eq $null) {
        $Global:CfgSiteCode = (Get-WmiObject -ComputerName $CfgSiteServer -Namespace root\sms -Class SMS_ProviderLocation -EA SilentlyContinue).SiteCode
        If (-Not $CfgSiteCode) {
            Write-Error "Could not obtain sitecode from $CfgSiteServer"
            return
        } Else {
            Write-Verbose "Found sitecode $CfgSitecode"
            Write-Verbose "Setting Global vars"
    
            If (-Not (Test-Path -Path (Split-Path -Path $VarFile -Parent))) {
                New-Item -Path (Split-Path -Path $VarFile -Parent) -ItemType Directory
            }

            Get-Variable Cfg* -Scope Global | Export-Clixml -Path $VarFile
        }
    }
}

function Connect-CfgSiteServer {
    <#
    .SYNOPSIS
        Setup global vars for other USC-SCCM module commandlets
    .DESCRIPTION
        Attempt to import global variables for other USC-SCCM module cmdlets, and if they don't exists, or the server cannot be contacted, prompt for input.
    .EXAMPLE
        Connect-CfgSiteServer

        Enter your site server hostname: 
    .NOTES
        Author: Jesse Harris
        Date: 01/06/2018
    .LINK
        https://github.com/zigford/USC-SCCM
    #>
    [CmdLetBinding()]
    Param()

    Import-CfgGlobalVars

}

function Test-CurrentAdminRights {
    #Return $True if process has admin rights, otherwise $False
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Role = [System.Security.Principal.WindowsBuiltinRole]::Administrator
    return (New-Object Security.Principal.WindowsPrincipal $User).IsInRole($Role)
 }

function Get-CfgCollectionMembers {
<#
    .SYNOPSIS
    Retreive members of an SCCM collection.
    
    .DESCRIPTION
    Connects to the primary site server and queries the WMI namespace for members of a collection, based on input.
    
    .PARAMETER Collection
    The descriptive name of a collection. If spaces are in the name, surround it by quotes.
    
    .EXAMPLE
    C:\PS>Get-CfgCollectionMembers "VMware vSphere Client 4.1 MSI WKS"
    ComputerName                                                Collection
	------------                                                ----------
	GMNQ12S                                                     VMware vSphere Client 4.1 MSI WKS
    
       
    .NOTES
    Author: Jesse Harris
    For: University of Sunshine Coast
    Date Created: 09 Jan 2012        
    ChangeLog:
    1.0 - First Release
#>
Param(
    [Parameter(Mandatory = $True, HelpMessage = "Please enter a collection name",
               ValueFromPipeLine = $true,
               ValueFromPipelinebyPropertyName = $True)]
               [ValidateNotNullOrEmpty()]
               [String[]]
               $Collection,$CfgSiteCode=$Global:CfgSiteCode, $CfgSiteServer=$Global:CfgSiteServer, $Property
               )
$Collections = Get-WmiObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" -Query `
    "Select * from SMS_Collection Where Name like '$Collection'"
ForEach ( $Col in $Collections ) {
    $Members = Get-WmiObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" -Query `
    "Select * from $($Col.MemberClassName)"
    #"$($Col.Name)"
      If ($Property) {
        $Members | Select-Object $Property
        }
      Else {
        $Members | Select-Object @{label='ComputerName';expression={$_.Name}},@{label='Collection';expression={$Col.Name}}
     }
}
}

function Get-CfgClientInventory {
<#
    .SYNOPSIS
    Retreive Inventory information of a Config Manager Client.
    
    .DESCRIPTION
    Connects to the primary site server and queries the WMI namespace for client inventory.
    
    .PARAMETER ComputerName
    The name of a ConfigMgr client, registered with the Site Server. The percent symbol can be used inplace as a wildcard.

    .PARAMETER PrimaryUser
    If the PrimaryUser parameter is used, a search will be performed for the ConfigMgr clients where the Resource is linked to the Primary user. The percent symbol can be used inplace as a wildcard.
	
	.PARAMETER UserName
	If the UserName parameter is used, a search will be performed for ConfigMgr clients where the username matches LastLogonUserName. The percent symbol can be used inplace as a wildcard.
	
	.PARAMETER Properties
	Use the Properties parameter to specify additonal properties to load. These properties have additional network/load cost as they create additional WMI queries.
    Available properties are: VLAN, Monitor(Returns MonitorCount and MonitorRes), DockStatus, Memory, Model Manufacturer, BuildInfo, Properties.
    
   .EXAMPLE
    C:\PS>Get-CfgClientInventory 6WMPSN1
    
	ComputerName      LastLogonUserName     IPAddresses
	------------      -----------------     ----------
	6WMPSN1           jpharris              {169.254.71.251, 172.16.70...
   
	.EXAMPLE
	C:\PS>Get-CfgClientInventory -UserName jpha%

	ComputerName      LastLogonUserName     IPAddresses
	------------      -----------------     ----------
	6WMPSN1           jpharris              {169.254.71.251, 172.16.70...
	VDI-WIN7X86-016   jpharris              {10.0.2.19, fe80::ed59:db1...    
	
	.EXAMPLE
	C:\PS>Get-CfgClientInventory 6WMPSN1 -Properties VLAN,Model,Monitor,DockStatus
		Returns additional properties of system 6wmpsn1
		
	.EXAMPLE
	C:\PS>Get-CfgClientInventory 6WMPSN1 -Property Name,IPAddresses,MACAddresses
	
	Name              IPAddresses                    Macaddresses
	----              -----------                    ------------
	6WMPSN1           203.57.189.58 				 00:50:56:C0:00:01
	
	.EXAMPLE
	C:\PS>Get-CfgCollectionMembers -Collection "Lab DG40" | Get-CfgClientInventory -Properties BuildInfo
		Returns Build times and management point for the collection members of Lab DG40
		
	.EXAMPLE
	C:\PS>Get-CfgClientInventory 6WMPSN1 | Select -ExpandProperty IPAddresses
	169.254.71.251
	172.16.70.159
	192.168.201.1
	203.57.189.153
	fe80::954a:bf66:6607:4206
	fe80::b1af:461b:efa:176
	fe80::b83a:7f75:cfcc:47fb
	fe80::fda2:bc20:ea38:6c80

    .EXAMPLE
    C:\PS>Get-CfgClientInventory -PrimaryUser '%jpharris' -Properties PrimaryUser

    ComputerName  LastLogonUserName IPAddresses     PrimaryUser
    ------------  ----------------- -----------     -----------
    049660345053  slawford          {10.205.80.33}  {USC\AdminJPHarris, usc\lgoldsbo, USC\slaw
    WSP-LICENSE01                   {10.104.0.191}  {usc\adminjpharris, usc\adminlgoldsbo


    .NOTES
    Author: Jesse Harris
    For: University of Sunshine Coast
    Date Created: 09 Jan 2012        
    ChangeLog:
    1.0 - First Release
    1.1 - 10/04/2012 - Modified default properties and docs
    1.2 - 19/04/2018 - Added PrimaryUser property and search on primary user

    .LINKS
    https://github.com/zigford/USC-SCCM
#>
  [CmdletBinding(DefaultParameterSetName="Computer")]

    Param(
        [Parameter(
            ValueFromPipeline=$True,
            ValueFromPipelinebyPropertyName=$True,
            ParameterSetName="Computer")]
        [Parameter(
            Position = 0    
        )]
        [string[]]$ComputerName="$env:computername",
        [Parameter(
            ParameterSetName="User"
        )]
        [string]$UserName,
        [Parameter(
            ParameterSetName="PrimaryUser"
        )]
        $PrimaryUser,
        $CfgSiteCode=$Global:CfgSiteCode,
        $CfgSiteServer=$Global:CfgSiteServer,
        $Properties,
        [Switch]$ExtendedData
    )
PROCESS {

      function CfgClientInventory-Worker {
        Param($Name,$User,$PrimaryUser)
        #Set Default Object properties
        $defaultProperties = @('ComputerName','LastLogonUserName', 'IPAddresses')

        If ($Name -ne $null) {
            $Query = "Select * from SMS_R_System Where Name like '$Name'"
            $QueryResults = Get-WmiObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" -Query $Query
        } ElseIf ($User) {
            $Query = "Select * from SMS_R_System Where LastLogonUserName like '$User'"
            $QueryResults = Get-WmiObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" -Query $Query
        } elseif ($PrimaryUser) {
            $UDAQuery = "Select * from SMS_UserMachineRelationship Where UniqueUserName like '$PrimaryUser'"
            $UDAResults = Get-WmiObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" -Query $UDAQuery
            $QueryResults = $UDAResults | ForEach-Object {
                Get-WmiObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" -Query "Select * from SMS_R_System Where ResourceID = '$($_.ResourceID)'"
            }
        }
        Foreach ($Result in $QueryResults) {
            $MonitorRes = $null
            $MonitorCount = $null
            $Result | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Result.Name
            Switch ($Properties) {
                <#VLAN { 
                    $VLANQuery = 'Select Ranges from SMS_G_System_USC_MOEVLAN Where ResourceID = "' + $Result.ResourceID + '"'
                    $Result | Add-Member -MemberType NoteProperty -Name VLAN -Value (Get-WMIObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" -Query $VLANQuery).Ranges
                    $defaultProperties += "VLAN"
                    }#>
                Model {
                    $ModelQuery = 'Select Model from SMS_G_System_COMPUTER_SYSTEM Where ResourceID = "' + $Result.ResourceID + '"'
                    $Result | Add-Member -MemberType NoteProperty -Name Model -Value (Get-WMIObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" -Query $ModelQuery).Model
                    $defaultProperties += "Model"
                    }
                PrimaryUser {
                    $PrimaryUserQuery = 'Select * from SMS_UserMachineRelationship Where ResourceID = "' + $Result.ResourceID + '"'
                    $UDAData = Get-WMIObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" -Query $PrimaryUserQuery
                    If ($UDAData) {
                        $Result | Add-Member -MemberType NoteProperty -Name PrimaryUser -Value $UDAData.UniqueUserName
                        $defaultProperties += "PrimaryUser"
                    }
                }
                Monitor {
                    $MonitorQuery = 'Select * from SMS_G_System_DESKTOP_MONITOR Where ResourceID = "' + $Result.ResourceID + '"'
                    $MonitorData = (Get-WMIObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" -Query $MonitorQuery)
                    $MonitorData | Where-Object {$_.ScreenWidth -ne $null} | ForEach-Object {$MonitorRes += "$($_.ScreenWidth)x$($_.ScreenHeight),"
                    $MonitorCount ++}
                    $MonitorRes = $MonitorRes -replace ",$",""
                    $Result | Add-Member -MemberType NoteProperty -Name MonitorCount -Value $MonitorCount
                    $Result | Add-Member -MemberType NoteProperty -Name MonitorRes -Value $MonitorRes
                    $defaultProperties += "MonitorCount","MonitorRes"
                    }
                Memory {
                    $MemoryQuery = 'Select TotalPhysicalMemory from SMS_G_System_X86_PC_MEMORY Where ResourceID = "' + $Result.ResourceID + '"'
                    $Number = (Get-WMIObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" -Query $MemoryQuery).TotalPhysicalMemory /1kb
                    $Memory = "{0:N0}" -f $Number + " MB"
                    $Result | Add-Member -MemberType NoteProperty -Name Memory -Value $Memory
                    $defaultProperties += "Memory"
                    }       
                Warranty {
                    $WarrantyQuery = 'Select WarrantyEndDate from SMS_G_System_USCWarrantyInfo Where ResourceID = "' + $Result.ResourceID + '"'
                    $Result | Add-Member -MemberType NoteProperty -Name WarrantyEndDate -Value (Get-WMIObject -ComputerName $CfgSiteServer -NameSpace "root\sms\site_$($CfgSiteCode)" -Query $WarrantyQuery).WarrantyEndDate
                    $defaultProperties += "WarrantyEndDate"
                    }
                <#DockStatus { 
                    $DockQuery = 'Select DockingState from SMS_G_System_USC_DOCKINFO Where ResourceID = "' + $Result.ResourceID + '"'
                    $DockStatus = Switch ((Get-WMIObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" -Query $DockQuery).DockingState) {
                        0 {"Unsupported"}
                        1 {"UnDocked"}
                        2 {"Docked"}
                        3 {"UnKnown"}
                    }
                    $Result | Add-Member -MemberType NoteProperty -Name DockStatus -Value $DockStatus
                    $defaultProperties += "DockStatus"
                    }#>
                VideoCard {
                    $VCardQuery = 'Select Description,DriverVersion from SMS_G_System_VIDEO_CONTROLLER Where ResourceID = "' + $Result.ResourceID + '"'
                    $VCard = (Get-WMIObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" -Query $VCardQuery)
                    $Result | Add-Member -MemberType NoteProperty -Name VideoCard -Value $VCard.Description
                    $Result | Add-Member -MemberType NoteProperty -Name DriverVersion -Value $VCard.DriverVersion
                    $defaultProperties += "VideoCard","DriverVersion"
                    }
                Manufacturer {
                    $ManufacturerQuery = 'Select Manufacturer from SMS_G_System_COMPUTER_SYSTEM Where ResourceID = "' + $Result.ResourceID + '"'
                    $Result | Add-Member -MemberType NoteProperty -Name Manufacturer -Value (Get-WMIObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" -Query $ManufacturerQuery).Manufacturer
                    $defaultProperties += "Manufacturer"
                    }
                BuildInfo {
                    $BuildInfoQuery = 'Select * from SMS_G_System_MOETATTOO Where ResourceID = "' + $Result.ResourceID + '"'
                    $BuildInfo = (Get-WMIObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" -Query $BuildInfoQuery)
                    ForEach ($Build in $BuildInfo) {
                        If ($Build.BuildTimestamp -ne $null) {
                            $Result | Add-Member -MemberType NoteProperty -Name BuildTimestamp -Value ([datetime]::ParseExact([string]$Build.BuildTimestamp,"yyyyMMddHHmmss.000000+600",$null))
                            $Result | Add-Member -MemberType NoteProperty -Name BuildManagementPoint -Value $Build.BuildManagementPoint
                            $Result | Add-Member -MemberType NoteProperty -Name BuildTSName -Value $Build.BuildTSName
                            $Result | Add-Member -MemberType NoteProperty -Name CoreImageTimestamp -Value ([datetime]::ParseExact([string]$Build.CoreImageTimestamp,"yyyyMMddHHmmss.000000+600",$null))
                            $Result | Add-Member -MemberType NoteProperty -Name CoreImageTSName -Value $Build.CoreImageTSName
                            $defaultProperties = @('ComputerName','BuildTimestamp','BuildTSName')
                        }
                    }
                }
                
            }
            $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet',[string[]]$defaultProperties)
            $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
            $Result | Add-Member MemberSet PSStandardMembers $PSStandardMembers -PassThru
        }
        
      }

    If ($UserName) { 
        CfgClientInventory-Worker -User $UserName
    } Elseif ($PrimaryUser) {
        CfgClientInventory-Worker -PrimaryUser $PrimaryUser
    } Else {
        If ($PSBoundParameters.ContainsKey('ComputerName')) {
            Foreach ($Computer in $ComputerName) {
                CfgClientInventory-Worker -Name $Computer
            } 
	    } Else {
		    CfgClientInventory-Worker -Name $ComputerName
        }
    }
  }
}

function Test-CfgCollectionMembers {
<#
    .SYNOPSIS
    Performs Test-Connection on the members of the specified collection.
    
    .DESCRIPTION
    Connects to the primary site server and queries the WMI namespace for members of a collection, then reports on their network connectivity.
    
    .PARAMETER Collection
    The descriptive name of a collection. If spaces are in the name, surround it by quotes.
    
   .EXAMPLE
    C:\PS>Test-CfgCollectionMembers
    
	87VZ72S is unavailable
	F7VZ72S is up
	67VZ72S is unavailable
	57VZ72S is up
	B7VZ72S is unavailable
	G7VZ72S is unavailable
	47VZ72S is unavailable
	28VZ72S is unavailable
	J7VZ72S is unavailable
		
    .NOTES
    Author: Jesse Harris
    For: University of Sunshine Coast
    Date Created: 09 Jan 2012        
    ChangeLog:
    1.0 - First Release
#>
Param($Collection, $CfgSiteCode=$Global:CfgSiteCode, $CfgSiteServer=$Global:CfgSiteServer,$TTL=2)
Get-CfgCollectionMembers -Collection $Collection | `
  ForEach-Object { 
        $TestConn = Test-Connection -TimeToLive $TTL -ComputerName $_.ComputerName -Count 1 -ErrorAction SilentlyContinue
        If ( $TestConn ) { 
            $_ | Add-Member -MemberType NoteProperty -Name "Online" -Value $True
            Try {
                $UserName = (Get-WmiObject -ComputerName $_.ComputerName -Class Win32_computersystem).UserName
            } Catch {
                $UserName = $False
            }
            If ($UserName.Count -gt 0 -and ($UserName.StartsWith('USC\'))) {$UserName = $UserName.TrimStart('USC\')}
            $_ | Add-Member -MemberType NoteProperty -Name "CurrentUser" -Value $UserName
            
        } Else {
            $_ | Add-Member -MemberType NoteProperty -Name "Online" -Value $False
            $_ | Add-Member -MemberType NoteProperty -Name "CurrentUser" -Value $False
        }
        $_
  }
}

function Send-CfgUserUpdateTrigger {
    Param($ComputerName)
    
    $sid = ( get-wmiobject -ComputerName $ComputerName -query "SELECT UserSID FROM CCM_UserLogonEvents WHERE LogoffTime = NULL" -namespace "ROOT\ccm").UserSID.replace('-','_');
    $sched=([wmi]"\\$ComputerName\root\ccm\Policy\$sid\ActualConfig:CCM_Scheduler_ScheduledMessage.ScheduledMessageID='{00000000-0000-0000-0000-000000000026}'");
    $sched.Triggers=@('SimpleInterval;Minutes=1;MaxRandomDelayMinutes=0');
    $sched.Put()
}


function Get-CfgCacheSize {
Param($ComputerName=$env:ComputerName)
    $Cache = ([WMI]"\\$ComputerName\Root\ccm\SoftmgmtAgent:CacheConfig.ConfigKey='Cache'").Size
    $Cache
}

function Get-CMCacheInfo {
    $OUIResource = New-Object -ComObject UIResource.UIResourceMgr
    $OUIResource.GetCacheInfo()
}

function Clear-CMCache {
    <#
    .SYNOPSIS
    Connects to the Config Manager client via Com object and requests cache deletion on items with a reference count of 0.
    
    .DESCRIPTION
    Connects to a PC using WinRM and invokes a script to cleanup cache items which are no longer in use by the client.
    
    .PARAMETER ComputerName
    The hostname of a computer to connect to. If omitted, works on the local host if there are sufficient rights.
    
   .EXAMPLE
    C:\PS>Get-CfgCollectionMembers | Clear-CMCache -Verbose
    
    VERBOSE: Attempting connection to SME-TEST02
    VERBOSE: Invoking Scriptblock
    VERBOSE: Getting cache object
    VERBOSE: Cache Location C:\WINDOWS\ccmcache\2s has 0 references. Deleting..
    VERBOSE: Cache Location C:\WINDOWS\ccmcache\2u has 0 references. Deleting..
    VERBOSE: Cache Location C:\WINDOWS\ccmcache\2v has 0 references. Deleting..
    VERBOSE: Cache Location C:\WINDOWS\ccmcache\2x cannot be removed as it has 1 reference.

    .NOTES
    Author: Jesse Harris
    For: University of Sunshine Coast
    Date Created: 05 Feb 2018        
    ChangeLog:
    1.0 - First Release
#>
    [CmdletBinding()]
    Param(
        [Parameter(
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True
        )]$ComputerName)
    Begin {
        $ScriptBlock = {
            [CmdletBinding()]
            Param($VerbosePreference)

            #$VerbosePreference = 'Continue'
            function Get-CMCacheInfo {
                [CmdLetBinding()]
                Param()

                $OUIResource = New-Object -ComObject UIResource.UIResourceMgr
                $OUIResource.GetCacheInfo()
            }
            Write-Verbose "Getting cache object"
            $Cache = Get-CMCacheInfo
            ForEach ($CacheObj in $Cache.GetCacheElements()) {
                Switch ($CacheObj.ReferenceCount) {
                    {$_ -gt 1} { Write-Verbose "Cache Location $($CacheObj.Location) cannot be removed as it has $($CacheObj.ReferenceCount) references." }
                    1 { Write-Verbose "Cache Location $($CacheObj.Location) cannot be removed as it has 1 reference." }
                    Default {
                        Write-Verbose "Cache Location $($CacheObj.Location) has 0 references. Deleting.."
                        Try {
                            $Cache.DeleteCacheElement($CacheObj.CacheElementId)
                        } Catch {
                            Write-Warning "Failed to remove cache location"
                        }
                    }
                }
            }
        }
    }

    Process {
        If ($ComputerName.ComputerName) {
            $ComputerName = $ComputerName.ComputerName
        }
        If ($ComputerName) {
            Write-Verbose "Attempting connection to $ComputerName"
            If (-Not (Test-Connection -ComputerName $ComputerName -Count 1 -TimeToLive 7 -Quiet)) {
                Write-Error "Device $ComputerName not online"
            } else {
                $WinRM = Get-Service -ComputerName $ComputerName -Name WinRM
                If ($WinRM.Status -eq 'Stopped') { $WinRM.Start() }
                If (-Not (Test-WSMan -ComputerName $ComputerName)) {
                    Write-Error 'Unable to connect to WinRM service'
                } else {
                    Write-Verbose "Invoking Scriptblock"
                    Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ArgumentList $VerbosePreference
                }
            }
        } else {
            Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $VerbosePreference
        }
    }
}

function Set-CfgCacheSize {
[CmdletBinding()]
Param($ComputerName=$env:ComputerName,$Size=25000,[Switch]$Percentage)
    If ($Percentage) {
        #Check if size is written in percent
        If ($Size -gt 99) {
            Write-Error "Size is not a percentage. Please specify size as a percentage when using the percentage parameter"
            return
        }
        #Okay, lets work out what the size will be if it is a percentage of the current disk.
        # 1. Get disk info
        $DiskInfo = Get-WmiObject -ComputerName $ComputerName -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq 'C:'}
        # 2. Get the freespace of C:
        $Freespace =$DiskInfo.FreeSpace 
        # 3. Get the full size of the disk
        $DiskSize = $DiskInfo.Size
        # 4. Work out the percentage of total size
        $PercentOfTotal = $DiskSize/100*$Size
        # 5. Do we have this amount available in freespace whilst retaining 10 gig for the OS
        If (($Freespace - $PercentOfTotal) -gt 10240) {
            #Yes we will be able to do this
            $FreeSpaceHR = "{0:#00}Gb" -f ($Freespace /1gb)
            $PercentOfTotalHR = "{0:#00}Gb" -f ($PercentOfTotal /1gb)
            Write-Verbose "Freespace is $FreeSpaceHR" 
            Write-Verbose "We will consume $PercentOfTotalHR"
            #Convert Bytes to Megabytes
            $SizeinMB = $PercentOfTotal/1024/1024
            $Size = [int]$SizeinMB
        } Else {
            #No, not enough space available
            Write-Error "Not enough space available to consume $Size % of disk"
            return
        }
    }
    
    $a=([wmi]"\\$ComputerName\ROOT\ccm\SoftMgmtAgent:CacheConfig.ConfigKey='Cache'")
    $a.Size=$Size
    $a.Put()
    If ($? -eq $true) {
        Write-Verbose "Succesfully set cache size to $Size Mb"
    }
}

function Send-CfgAppEval {
<#
    .SYNOPSIS
    Performs a Application Deployment evaluation cycle on the specified ConfigMgr client.
    
    .DESCRIPTION
    Connect to the WMI namespace of the specified machine and executes a method to trigger the schedule
    
    .PARAMETER ComputerName
    The name of a ConfigMgr client, registered with the Site Server.
    
   .EXAMPLE
    C:\PS>Send-CfgAppEval -ComputerName 9k9562s
	Executing AppEval for 9k9562s
	
	.EXAMPLE
	Get-CfgCollectionMembers -Collection "Lab DG40" | Send-CfgAppEval
		Attempts to send an application deployment cycle to members of the collection "Lab DG40"
		
    .NOTES
    Author: Jesse Harris
    For: University of Sunshine Coast
    Date Created: 09 Jan 2012        
    ChangeLog:
    1.0 - First Release
#>
  [CmdletBinding()]

      Param(
      [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
      [string[]]$ComputerName)
PROCESS {

	function SendMachineUpdate-Worker {
		Param($sName)
		$SCCMClient = [WMIClass]"\\$sName\Root\CCM:SMS_Client"
		Write-Host "Executing AppEval for $sName"
		Try {$SCCMClient.psbase.InvokeMethod("TriggerSchedule", "{00000000-0000-0000-0000-000000000121}") }
		Catch { "An Error occured" }
	}
	
	If ($PSBoundParameters.ContainsKey('ComputerName')) {
		ForEach ($Computer in $ComputerName) {
			SendMachineUpdate-Worker -sName $Computer
			}
		} Else {
			SendMachineUpdate-Worker -sName $ComputerName
		}
	}
}

function Send-CfgTrigger {
<#
    .SYNOPSIS
    Performs a machine policy update on the specified ConfigMgr client.
    
    .DESCRIPTION
    Connect to the WMI namespace of the specified machine and executes a method to download and evaluate machine policy
    
    .PARAMETER ComputerName
    The name of a ConfigMgr client, registered with the Site Server.
    
   .EXAMPLE
    C:\PS>Send-CfgSCEPTrigger -ComputerName 9k9562s
	Downloading Policy for 9k9562s
	Evaluating Policy for 9k9562s
	
	.EXAMPLE
	Get-CfgCollectionMembers -Collection "Lab DG40" | Send-CfgSCEPTrigger
		Attempts to send a machine policy update evaluation to members of the collection "Lab DG40"
		
    .NOTES
    Author: Jesse Harris
    For: University of Sunshine Coast
    Date Created: 09 Jan 2012        
    ChangeLog:
    1.0 - First Release
#>
  [CmdletBinding()]

      Param(
      [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
      [string[]]$ComputerName,
	  [ValidateSet(
          'Machine',
          'User',
          'HWInventory',
          'SCEP',
          'UpdateScan'
          )][string[]]$TriggerName)
	  
BEGIN {
    $Delay = 1
	$Triggers = Switch ($TriggerName) {
		Machine {'{00000000-0000-0000-0000-000000000021}','{00000000-0000-0000-0000-000000000022}'}
		User {'{00000000-0000-0000-0000-000000000026}','{00000000-0000-0000-0000-000000000027}' }
		HWInventory {'{00000000-0000-0000-0000-000000000001}'}
		SWInventory {'{00000000-0000-0000-0000-000000000002}'}
		SCEP {'{00000000-0000-0000-0000-000000000221}'}
        UpdateScan {
            '{00000000-0000-0000-0000-000000000113}','{00000000-0000-0000-0000-000000000108}'
            $Delay = 15    }
		Default {'{00000000-0000-0000-0000-000000000021}','{00000000-0000-0000-0000-000000000022}'}
	}
}
PROCESS {

	function SendMachineUpdate-Worker {
		Param($sName,$Trigger,$Delay)
		$SCCMClient = [WMIClass]"\\$sName\Root\CCM:SMS_Client"
		Write-Verbose "Executing trigger $Trigger on $sName"
		Try {$SCCMClient.psbase.InvokeMethod("TriggerSchedule", $Trigger) }
		Catch { "An Error occured" }
        Write-Verbose "Sleeping for $Delay Seconds"
		Start-Sleep -Seconds $Delay
	}
	
	If ($PSBoundParameters.ContainsKey('ComputerName')) {
		ForEach ($Computer in $ComputerName) {
			$Triggers | ForEach-Object { SendMachineUpdate-Worker -sName $Computer -Trigger $_ -Delay $Delay }
			}
		} Else {
			$Triggers | ForEach-Object { SendMachineUpdate-Worker -sName $ComputerName -Trigger $_ -Delay $Delay}
		}
	}
}

function Send-CfgSCEPTrigger {
<#
    .SYNOPSIS
    Performs a machine policy update on the specified ConfigMgr client.
    
    .DESCRIPTION
    Connect to the WMI namespace of the specified machine and executes a method to download and evaluate machine policy
    
    .PARAMETER ComputerName
    The name of a ConfigMgr client, registered with the Site Server.
    
   .EXAMPLE
    C:\PS>Send-CfgSCEPTrigger -ComputerName 9k9562s
	Downloading Policy for 9k9562s
	Evaluating Policy for 9k9562s
	
	.EXAMPLE
	Get-CfgCollectionMembers -Collection "Lab DG40" | Send-Send-CfgSCEPTrigger
		Attempts to send a machine policy update evaluation to members of the collection "Lab DG40"
		
    .NOTES
    Author: Jesse Harris
    For: University of Sunshine Coast
    Date Created: 09 Jan 2012        
    ChangeLog:
    1.0 - First Release
#>
  [CmdletBinding()]

      Param(
      [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
      [string[]]$ComputerName)
PROCESS {

	function SendMachineUpdate-Worker {
		Param($sName)
		$SCCMClient = [WMIClass]"\\$sName\Root\CCM:SMS_Client"
		Write-Host "Downloading Policy for $sName"
		Try {$SCCMClient.psbase.InvokeMethod("TriggerSchedule", "{00000000-0000-0000-0000-000000000221}") }
		Catch { "An Error occured" }
	}
	
	If ($PSBoundParameters.ContainsKey('ComputerName')) {
		ForEach ($Computer in $ComputerName) {
			SendMachineUpdate-Worker -sName $Computer
			}
		} Else {
			SendMachineUpdate-Worker -sName $ComputerName
		}
	}
}

function Send-CfgMachineUpdateTrigger {
<#
    .SYNOPSIS
    Performs a machine policy update on the specified ConfigMgr client.
    
    .DESCRIPTION
    Connect to the WMI namespace of the specified machine and executes a method to download and evaluate machine policy
    
    .PARAMETER ComputerName
    The name of a ConfigMgr client, registered with the Site Server.

    .PARAMETER Force
    Send a hard policy reset prior to a regular machine policy evlauation cyle
    
   .EXAMPLE
    C:\PS>Send-CfgMachineUpdateTrigger -ComputerName 9k9562s
	Downloading Policy for 9k9562s
	Evaluating Policy for 9k9562s
	
	.EXAMPLE
	Get-CfgCollectionMembers -Collection "Lab DG40" | Send-CfgMachineUpdateTrigger
		Attempts to send a machine policy update evaluation to members of the collection "Lab DG40"
		
    .NOTES
    Author: Jesse Harris
    For: University of Sunshine Coast
    Date Created: 09 Jan 2012        
    ChangeLog:
    1.0 - First Release
#>
  [CmdletBinding()]

      Param(
      [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
      [string[]]$ComputerName,
      [switch]$Force,
      [switch]$Confirm=$True)
PROCESS {

	function SendMachineUpdate-Worker {
		Param($sName)
		$SCCMClient = [WMIClass]"\\$sName\Root\CCM:SMS_Client"
        If ($Force) {
            If ($Confirm) {
                While ($ans -notin 'y','n') {
                    $ans = Read-Host -Prompt "Using the force parameter will cause a full machine policy reset. Are you sure you wish to continue ? (y/n)"
                }
                If ($ans -eq 'y') {
                    $AllowReset = $True
                }
            } else {
                $AllowReset = $True
            }
            If ($AllowReset) {
                Write-Verbose "Forcing policy reset"
                $SCCMClient.ResetPolicy(1)
                $SCCMClient.psbase.InvokeMethod("TriggerSchedule", "{00000000-0000-0000-0000-000000000040}")
            }
        }
		Write-Verbose "Downloading Policy for $sName"
		Try {$SCCMClient.psbase.InvokeMethod("TriggerSchedule", "{00000000-0000-0000-0000-000000000021}") }
		Catch { "An Error occured" }
		Start-Sleep -Seconds 2
		Write-Verbose "Evaluating Policy for $sName"
		Try {$SCCMClient.psbase.InvokeMethod("TriggerSchedule", "{00000000-0000-0000-0000-000000000022}") }
		Catch { "An Error occured" }
	}
	
	If ($PSBoundParameters.ContainsKey('ComputerName')) {
		ForEach ($Computer in $ComputerName) {
			SendMachineUpdate-Worker -sName $Computer
			}
		} Else {
			SendMachineUpdate-Worker -sName $ComputerName
		}
	}
}

function Send-CfgInventoryUpdateTrigger {
<#
    .SYNOPSIS
    Performs a hardware inventory on the specified ConfigMgr client.
    
    .DESCRIPTION
    Connect to the WMI namespace of the specified machine and executes a method to execute hardware inventory
    
    .PARAMETER ComputerName
    The name of a ConfigMgr client, registered with the Site Server.

    .PARAMETER Full
    Forces a full inventory report rather than a delta. This is achived by deleting the previous inventory which causes a version mismatch.
    
   .EXAMPLE
    C:\PS>Send-CfgInventoryUpdateTrigger -ComputerName 9k9562s
	
	.EXAMPLE
	Get-CfgCollectionMembers -Collection "Lab DG40" | Send-CfgInventoryUpdateTrigger
		Attempts to send a WMI method to execute hardware inventory update to members of the collection "Lab DG40"
		
    .NOTES
    Author: Jesse Harris
    For: University of Sunshine Coast
    Date Created: 09 Jan 2012        
    ChangeLog:
    1.0 - First Release
#>
Param($ComputerName,[switch]$Full)
If ($Full) {
    $invVersion = Get-WmiObject -ComputerName $ComputerName -Namespace Root\ccm\invagt -Class InventoryActionStatus | Where-Object {$_.InventoryActionID -eq "{00000000-0000-0000-0000-000000000001}"}
    $invVersion.Delete()
}
If ( ($ComputerName) ) {
$SCCMClient = [WMIClass]"\\$ComputerName\Root\CCM:SMS_Client"
}
Else { 
$SCCMClient = [WMIClass]"Root\CCM:SMS_Client"
}
$SCCMClient.TriggerSchedule("{00000000-0000-0000-0000-000000000001}")
}

function Get-CfgClientProvisioningMode {
  (Get-ItemProperty "HKLM:\Software\Microsoft\CCM\CCMExec" -Name "ProvisioningMode").ProvisioningMode
}

function Set-CfgClientProvisioningMode {
   Set-ItemProperty "HKLM:\Software\Microsoft\CCM\CCMExec" -Name "ProvisioningMode" -Value "False" -Force
   Set-ItemProperty "HKLM:\Software\Microsoft\CCM\CCMExec" -Name "SystemTaskExcludes" -Value "" -Force
   Remove-ItemProperty -Path "HKLM:\Software\Microsoft\SMS\Task Sequence" -Name Package -ea SilentlyContinue
   Remove-ItemProperty -Path "HKLM:\Software\Microsoft\SMS\Task Sequence" -Name "Active Request Handle" -ea SilentlyContinue
   Remove-ItemProperty -Path "HKLM:\Software\Microsoft\SMS\Task Sequence" -Name CleanUpFolder -ea SilentlyContinue
   Remove-ItemProperty -Path "HKLM:\Software\Microsoft\SMS\Task Sequence" -Name Program -ErrorAction SilentlyContinue
}

function Get-CfgCollections {
    <# 
            .SYNOPSIS 
                Determine the SCCM collection membership    
            .DESCRIPTION
                This function allows you to determine the SCCM collection membership of a given user/computer
            .PARAMETER  Type 
                Specify the type of member you are querying. Possible values : 'User' or 'Computer'
            .PARAMETER  ResourceName 
                Specify the name of your member : username or computername
            .EXAMPLE 
                Get-Collections -Type computer -ResourceName PC001
                Get-Collections -Type user -ResourceName User01
            .Notes 
                Author : Antoine DELRUE 
                Edited : Jesse Harris
                WebSite: http://obilan.be 
    #> 
    [CmdLetBinding()]
      param(
    [Parameter(Mandatory=$false,Position=2)]
    [ValidateSet("User", "Computer")]
    [string]$type="Computer",

    [Parameter(Mandatory=$true,Position=1)]
    [string]$ResourceName,
    $CfgSiteServer=$Global:CfgSiteServer,
    $CfgSiteCode=$Global:CfgSiteCode
    ) #end param

    Switch ($type)
        {
            User {
                Try {
                    $ErrorActionPreference = 'Stop'
                    $resource = Get-WmiObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$CfgSiteCode" -Class "SMS_R_User" | ? {$_.Name -ilike "*$resourceName*"}                            
                }
                catch {
                    Write-Warning ('Failed to access "{0}" : {1}' -f $CfgSiteServer, $_.Exception.Message)
                }

            }

            Computer {
                Try {
                    $ErrorActionPreference = 'Stop'
                    $resource = Get-WmiObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$CfgSiteCode" -Class "SMS_R_System" | ? {$_.Name -ilike "$resourceName"}                           
                }
                catch {
                    Write-Warning ('Failed to access "{0}" : {1}' -f $CfgSiteServer, $_.Exception.Message)
                }
            }
        }

    $ids = (Get-WmiObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$CfgSiteCode" -Class SMS_CollectionMember_a -filter "ResourceID=`"$($Resource.ResourceId)`"").collectionID
    # A little trick to make the function work with SCCM 2012
    if ($ids -eq $null)
    {
            $ids = (Get-WmiObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$CfgSiteCode" -Class SMS_FullCollectionMembership -filter "ResourceID=`"$($Resource.ResourceId)`"").collectionID
    }

    $array = @()

    foreach ($id in $ids)
    {
        $Collection = get-WMIObject -ComputerName $CfgSiteServer -namespace "root\sms\site_$CfgSiteCode" -class sms_collection -Filter "collectionid=`"$($id)`""
        $Object = New-Object PSObject
        $Object | Add-Member -MemberType NoteProperty -Name "CollectionName" -Value $Collection.Name
        $Object | Add-Member -MemberType NoteProperty -Name "CollectionID" -Value $id
        $Object | Add-Member -MemberType NoteProperty -Name "Comment" -Value $Collection.Comment
        $array += $Object
    }

    $array
}

function Get-CfgMachineVariables {
    <#
        .SYNOPSIS
            Determin all variables a machine has assigned
        .DESCRIPTION
            This function allows you to see machine and collection based variables a machine will eventually have
        .PARAMETER ComputerName
            Specify the name of the computer you want to query of variables
        .PARAMETER IncludeCollections
            Switch to also query collections. Disabled by default as it incurrs siginificant processing cost
        .EXAMPLE
            Get-CfgMachineVariables -ComputerName SME-Test03 -IncludeCollections
        .NOTES
            Author : Jesse Harris
            Website: github.com\zigford
            Version 1.1 - 25/01/2018 - Added collection precedence property
    #>
  [CmdletBinding()]

      Param(
      [Parameter(ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
      [string[]]$ComputerName="$env:computername",
      [Switch]$IncludeCollections,
      $CfgSiteCode=$Global:CfgSiteCode, $CfgSiteServer=$Global:CfgSiteServer,$Property)
PROCESS {

      function CfgClientInventory-Worker {
        Param($Name)
        $ResourceID = Get-WmiObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" `
            -Query "Select ResourceID from SMS_R_System Where Name = '$Name'" | Select-Object -ExpandProperty ResourceID
        Write-Verbose "ResourceID = $ResourceID"

        function Get-MachineLevelVars {
            Param($ResourceID)
            Write-Verbose "Getting machine level vars"
            $QueryResults = Get-WmiObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" `
                -Query "Select * from SMS_MachineSettings Where ResourceID = '$ResourceID'"
            $QueryResults.Get()
            ForEach ($Var in $QueryResults.MachineVariables) {
                [PSCustomObject]@{
                    'ComputerName' = $Name
                    'Name' = $Var.Name
                    'Value' = $Var.Value
                    'Source' = $Name
                    'Precedence' = 0
                }
            }
         
        }

        function Get-CollectionLevelVars {
            Param($Name)
            Write-Verbose "Getting collection level vars"
            Get-CfgCollections -type Computer -ResourceName $Name | ForEach-Object {
                $QueryResult = Get-WmiObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" -Query `
                    "Select * From SMS_CollectionSettings Where CollectionID = '$($_.CollectionID)'"
                Write-Verbose "Running Get Method on $($_.CollectionName) with CollectionID $($_.CollectionID)"
                If ($QueryResult) {
                    $QueryResult.Get()
                    ForEach ($Var in $QueryResult.CollectionVariables) {
                        [PSCustomObject]@{
                            'ComputerName' = $Name
                            'Name' = $Var.Name
                            'Value' = $Var.Value
                            'Source' = $_.CollectionName
                            'Precedence' = $QueryResult.CollectionVariablePrecedence
                        }
                    }
                }
            }           
        }

        Get-MachineLevelVars -ResourceID $ResourceID
        If ($IncludeCollections) {
            Get-CollectionLevelVars -Name $Name
        }
}

If ($PSBoundParameters.ContainsKey('ComputerName')) {
      Foreach ($Computer in $ComputerName) {
        CfgClientInventory-Worker -Name $Computer
      } 
	} Else {
		CfgClientInventory-Worker -Name $ComputerName
    }
  }
}

function Send-WOL {
    <#
        .SYNOPSIS
        Sends a WOL magic packet to wake a ConfigMgr client.
        
        .DESCRIPTION
        Connect to the WMI namespace of the site server, retreives the MAC addresses of a specified ConfigMgr client and generates WOL packets for each of those MAC addresses.
        
        .PARAMETER ComputerName
        The name of a ConfigMgr client, registered with the Site Server.
        
       .EXAMPLE
        C:\PS>Send-WOL -ComputerName 6wmpsn1
        Wake-On-Lan magic packet of length 102 sent to 00:50:56:C0:00:01
    
        Wake-On-Lan magic packet of length 102 sent to 00:50:56:C0:00:08
    
        Wake-On-Lan magic packet of length 102 sent to 1C:65:9D:98:8E:84
    
        Wake-On-Lan magic packet of length 102 sent to F0:4D:A2:59:80:4F
        
        .EXAMPLE
        Get-CfgCollectionMembers -Collection "Lab DG40" | Send-WOL
            Sends a WOL magic packet for MAC addresses of members of collection Lab DG40
            
        .NOTES
        Author: Jesse Harris
        For: University of Sunshine Coast
        Date Created: 09 Jan 2012        
        ChangeLog:
        1.0 - First Release
        1.1 - 10/04/2012 - Tests admin rights to bind on privlidged ports and sends wol on port 1230 and port 9
    #>
    param(
        [CmdletBinding()]
        [Parameter(ValueFromPipeline = $True, ValueFromPipelinebyPropertyName = $True)]
        [string[]]$ComputerName = "$env:computername",
        $SendFrom,
        [switch]$BroadCast,
        $Ports = 9,
        $CfgSiteCode = $Global:CfgSiteCode, $CfgSiteServer = $Global:CfgSiteServer, $MacAddress)

    BEGIN {
        $Proxies = @{}
    }
    PROCESS {
        function Send-WolWorker {
            Param($Name, $Port, $MacAddress, $From, [Switch]$BroadCast)
            $BroadcastString = if ($Broadcast) { "Broadcast"} else {"Unicast"}
            $FromString = if ($From) { "From $From" } else { "From this machine" }
            write-verbose "Initiating WOL - $FromString To: $Name Port: $Port $Broadcaststring"
            $Query = "Select MACAddresses,IPAddresses from SMS_R_System Where SMS_R_System.Name = '$Name' AND SMS_R_System.Active = '1'"
            $MachineResults = Get-WmiObject -ComputerName $CfgSiteServer -Namespace Root\SMS\Site_$CfgSiteCode -Query $Query
            If ( $MachineResults -eq $null ) {
                write-warning "No SCCM info returned for machine $Name"
                return 0
            }
            Foreach ($MachineResult in $MachineResults) {
                If ( $MachineResult.MacAddresses -eq $null ) {
                    write-warning "No Mac addresses found for $Name"
                    return 0
                }
                Foreach ($MacAddress in $MachineResult.MacAddresses) {
                    If ($BroadCast) {
                        $IPDests = '255.255.255.255'
                    }
                    Else {
                        $IPDests = $MachineResults.IPAddresses
                    }

                    ForEach ($IPDest in $IPDests) {
                        $ParsedIP = [System.Net.IPAddress]::Parse($IPDest)
                        If ($ParsedIP.AddressFamily -eq 'InterNetwork') {
                            Write-Verbose "$($ParsedIP.IPAddressToString) detected as IPv4"
                            $mac = $MacAddress.split(':') | % { [byte]('0x' + $_) }
                            $ScriptBlock = {
                                [CmdLetBinding()]
                                Param($Port, $mac, $ParsedIP, $VerbosePreference)
                                Write-Verbose "Parsed IP: $($ParsedIP.IPAddressToString)"
                                Write-Verbose "Port: $Port"
                                $packet = [byte[]](, 0xFF * 6)
                                $packet += $mac * 16
                                Write-Verbose "Packet Len: $($packet.Length)"
                                $UDPclient = new-Object System.Net.Sockets.UdpClient
                                $UDPclient.Connect($ParsedIP, $Port)
                                [void] $UDPclient.Send($packet, $packet.Length)
                            }
                            If ($From -ne $null) {
                                Invoke-command -AsJob -ComputerName $From -ScriptBlock $ScriptBlock -ArgumentList $Port, $mac, $ParsedIP, $VerbosePreference > $Null
                                Write-Verbose "Wake-On-Lan magic packet sent to port $Port on $Name $MacAddress from $From as broadcast`n"
                            }
                            else {
                                Invoke-Command $ScriptBlock -ArgumentList $Port, $mac, $ParsedIP, $VerbosePreference
                                Write-Verbose "Wake-On-Lan magic packet sent to port $Port on $Name $MacAddress from localhost as unicast`n"
                            }
                        }
                    }
                }
            }
        }
        function Test-SendFrom($SendFrom) {
            If (-not ($SendFrom -and (Test-Connection -ComputerName $SendFrom -Count 1 -Quiet))) {
                Write-Verbose "Neighbour $SendFrom down"
                return $null
            }

            $WinRM = Get-Service -ComputerName $SendFrom -Name WinRM

            If ($WinRM.Status -eq 'Stopped') { $WinRM.Start() }

            If (Test-WSMan -ComputerName $SendFrom -ErrorAction SilentlyContinue) {
                Return $SendFrom
            }
            Else {
                Write-Warning "Neighbour $SendFrom unable to use WinRM"
                return $null
            }
        }

        function Find-WOLProxyOnSubnet($IPSubnet) {
            # Get a machine on $IPSubnet that can be used to send WOL via WinRM
            $MachinesOnSameIP = Get-WmiObject -ComputerName $CfgSiteServer -Namespace root\sms\site_$CfgSiteCode -Query "Select Name from SMS_R_SYSTEM Where IPADDRESSES Like ""$($IPSubnet)"""
            $TotalCountMachinesOnSameIP = $MachinesOnSameIP.Count
            $MachinesOnSameIP = $MachinesOnSameIP.Name | Test-Pingable | ? { $_.Up }
            $MachinesOnSameIP = $MachinesOnSameIP.ComputerName
            write-verbose "Found $($MachinesOnSameIP.Count) pingable computers out of $TotalCountMachinesOnSameIP neighbours"
            $WorkingMachine = $null
            Foreach ($Machine in $MachinesOnSameIP) {
                # Write-Verbose "Testing $Machine.."
                $WorkingMachine = Test-SendFrom -SendFrom $Machine
                if ($WorkingMachine) {
                    Write-Verbose "Can send from $WorkingMachine"
                    break
                }
            }
            return $WorkingMachine   
        }

        function Get-WOLProxyOnSubnet($IPSubnet) {
            # Memoizing wrapper for Find-WOLProxyOnSubnet()
            if ($Proxies[$IPSubnet].Scanned) {
                write-Verbose "$IPSubnet scanned already"
                $WorkingMachine = $Proxies[$IPSubnet].WorkingMachine

                # Double check it still works
                if (Test-SendFrom($WorkingMachine)) {
                    return $WorkingMachine
                    # Otherwise we will rescan subnet again :-(
                }
            }

            write-verbose "Scanning $IPSubnet to find neighbour machine to send broadcast WOL"
            $WorkingMachine = Find-WOLProxyOnSubnet($IPSubnet)
            $Proxies[$IPSubnet] = [PSCustomObject]@{
                Scanned        = $True
                WorkingMachine = $WorkingMachine
            }                
            return $WorkingMachine   
        }

        function Get-IPFromSCCM ($Computer) {
            $Query = "Select IPAddresses from SMS_R_System Where SMS_R_System.Name = '$Computer' AND SMS_R_System.Active = '1'"
            $IPResults = Get-WmiObject -ComputerName $CfgSiteServer -Namespace Root\SMS\Site_$CfgSiteCode -Query $Query
            $IPV4Addr = ""
            ForEach ($IPDest in $IPResults.ipaddresses) {
                $ParsedIP = [System.Net.IPAddress]::Parse($IPDest)
                If ($ParsedIP.AddressFamily -eq 'InterNetwork') {
                    $IPV4Addr = $ParsedIP.IPAddressToString
                }
            }
            Return $IPV4Addr
        }

        # Main
        If (! $BroadCast -and ! $SendFrom){
            # Admin rights is only relevant for local packets. Skip admin check if Broadcast is specified
            if (! (Test-CurrentAdminRights)) { Write-Warning "Please run as Admin"; return }
        }
        If ($SendFrom) {
            $WinRMHost = Test-SendFrom -SendFrom $SendFrom
        }

        If ($PSBoundParameters.ContainsKey('ComputerName')) {
            Foreach ($Computer in $ComputerName) {
                #write-host "`nSending WOL to $Computer"
                If ($BroadCast) {
                    #Get the IP Address/Subnet of a machine (assuming 24 bit netmask)
                    try {
                        $IPOctets = @()
                        $IPOctets = ([System.Net.DNS]::GetHostByName($Computer)).AddressList.IPAddressToString.Split('.')
                    } catch {
                        Write-Verbose "DNS unable to resolve $Computer."
                        $IPV4Addr = Get-IPFromSCCM($Computer)
                        If ($IPV4Addr) {
                            write-verbose "SCCM has IPv4 address of $IPV4Addr recorded for $Computer"
                            $IPOctets = $IPV4Addr -split "\."
                        } else {
                            write-verbose "SCCM also has no recorded IPv4 address for $Computer. I give up on this one."
                            Continue
                        }
                    }
                    $IPSubnet = "$($IPOctets[0]).$($IPOctets[1]).$($IPOctets[2]).%"
                    $Proxy = Get-WOLProxyOnSubnet($IPSubnet)
                    If ($Proxy) {
                        ForEach ($Port in $Ports) {
                            Send-WolWorker -Name $Computer -Port $Port -From $Proxy -BroadCast
                        }
                    } Else {
                        Write-Verbose -Message "No usable machines on same subnet were found to forward WOL. soz."
                    }
                } Else {
                    ForEach ($Port in $Ports) {
                        Send-WolWorker -Name $Computer -Port $Port -From $WinRMHost
                    }
                }
            }
        } Else {
            # Probs can be removed
            ForEach ($Port in $Ports) {
                If ($MacAddress) {
                    Send-WolWorker -MacAddress $MacAddress -Port $Port -From $WinRMHost
                }
                Else {
                    Send-WolWorker -Name $ComputerName -Port $Port -From $WinRMHost
                }
            }
        }
    }
}

function Test-Pingable {
    <#
    .SYNOPSIS
    Parallel pingerer. Promptly pings a plethora of pooters in parallel. Returns a list of computers and whether they are up or not.
    
    .PARAMETER ComputerName
    Computer name to ping

    .EXAMPLE
    Test-pingable PC12ABC
    Get-CfgCollectionMembers "Lab DG35" | Test-Pingable
    
    .NOTES
    Author: Darryl Rees
    Date Created: 24 November 2017     
    ChangeLog:
    #>

    Param (
        [Alias("Name","Computer")][Parameter(ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string[]]$ComputerName
    )

    Begin {
        $jobs=@()
        $Computers=@()
    }
    Process {
        $NumPings = 3
        $jobs = $jobs + (test-connection $ComputerName -count $NumPings -asjob)
        $Computers = $Computers + $ComputerName
    }
    End {
        $pingresults = $jobs | receive-job -wait | select address, responsetime | group -ashash -asstring address
        # Now put back into the original order they were passed, and
        # check to see if a single echo/ping request returned with a non-null responsetime
        Foreach ($Computer in $Computers) {
            [PSCustomObject]@{
                ComputerName = $Computer
                Up = (($PingResults.$Computer | measure-object -property responsetime -maximum).maximum -ne $Null)
            }
        }
    }
}


function Get-CfgIPAddress {
<#
    .SYNOPSIS
    Uses Get-CfgClientInventory to quickly return IP addresses for a specific computer.
    
    .DESCRIPTION
    A shortcut to 'Get-CfgClientInventory -ComputerName xxxxxxx -Property IPAddresses | Select-Object -Property IPAddresses
    
    .PARAMETER ComputerName
    The name of a ConfigMgr client, registered with the Site Server.
    
   .EXAMPLE
    C:\PS>Get-CfgIPAddress 6WMPSN1
	169.254.71.251
	172.16.7.30
	192.168.201.1
	203.57.189.153
	fe80::954a:bf66:6607:4206
	fe80::b1af:461b:efa:176
	fe80::b83a:7f75:cfcc:47fb
	fe80::fda2:bc20:ea38:6c80
	
	.EXAMPLE
	Get-CfgCollectionMembers -Collection "Lab DG40" | Get-CfgIPAddress
		Gets the IPAddresses of members of collection Lab DG40
		
    .NOTES
    Author: Jesse Harris
    For: University of Sunshine Coast
    Date Created: 09 Jan 2012        
    ChangeLog:
    1.0 - First Release
#>
param(
      [Parameter(ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
      [string[]]$ComputerName="$env:computername",
      $CfgSiteCode=$Global:CfgSiteCode, $CfgSiteServer=$Global:CfgSiteServer)
PROCESS {
    
    function Get-CfgIPWorker {
        Param($Name)
        (Get-CfgClientInventory -ComputerName $Name -Property IPAddresses).IPAddresses
    }

If ($PSBoundParameters.ContainsKey('ComputerName')) {
      Foreach ($Computer in $ComputerName) {
        Get-CfgIPWorker -Name $Computer
      } 
	} Else {
		Get-CfgIPWorker -Name $ComputerName
    }
  }
}

function Send-RepairCCM {
<#
    .SYNOPSIS
    Attempts to repair a ConfigMgr client by sending a WMI method which uses MSI repair function.
    
    .DESCRIPTION
    Connects to the specified machines WMI namespace and runs a repair. If the Force parameter is used, the client is fully uninstalled and re-installed and the WMI repository is rebuilt.
    
    .PARAMETER ComputerName
    The hostname of a computer where you can connect and have administrator privileges.
	
	.PARAMETER Force
	Causes the client to be uninstalled, WMI service stopped, WMI repository renamed, WMI restarted and client re-installed.
    
   .EXAMPLE
    C:\PS>Send-RepairCCM 6wmpsn1
	Uninstalling SCCM Client...
	Success
	Force option: Rebuilding WMI
	Stopping WMI
	Renaming Repository
	Renamed \\9k9562s\c$\windows\Syswow64\wbem\Repository
	Renamed \\9k9562s\c$\windows\system32\wbem\Repository
	Restarting WMI
	SharedAccess would not start
	CCMExec gone. re-installing...
	Success
	
    .NOTES
    Author: Jesse Harris
    For: University of Sunshine Coast
    Date Created: 09 Jan 2012        
    ChangeLog:
    1.0 - First Release
#>
  [CmdletBinding()]

      Param(
      [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
      [string[]]$ComputerName,[Switch]$Force)
PROCESS {

      function RepairCCM-Worker {
        Param($Name)
		If ($Force) {    
			
			function Send-RemoteCommand {
				Param($Command,$Arguements,$ComputerName,[Switch]$NoWait)
				If ($NoWait) { $Options = "-d" }
				psexec.exe \\$ComputerName -s "$Command" $Arguements $Options 2>Null
				If ($LASTEXITCODE -eq 0) {Write-Host -ForegroundColor Green "Success" } Else {Write-Host -ForegroundColor Red "Fail"; return 1}
			}
			function Test-Service {
				Param($ServiceName,$ComputerName,$Action)
				$Service = Get-Service -ComputerName $ComputerName -Name $ServiceName
				If ( $Action -eq "Stop" ) {If ($Service.Status -eq "Running") {Try {$Service.Stop()} Catch {"$($Service.Name) would not stop"}}}
				If ( $Action -eq "Start") {If ($Service.Status -eq "Stopped") {Try {$Service.Start()} Catch {"$($Service.Name) would not start"}}}
			}
				

			#Setup Commands
			$InstallCommand = "\\wsp-configmgr01\SMS_SC1\Client\ccmsetup.exe /mp:wsp-configmgr01.usc.internal /force SMSSITECODE=SC1 SMSSLP=wsp-configmgr01.usc.internal DNSSUFFIX=USC.INTERNAL SMSMP=wsp-configmgr01.usc.internal"
			$UninstallCommand = "\\wsp-configmgr01\SMS_SC1\Client\ccmsetup.exe /Uninstall"
			#Get Architechture
			
				$SYS = "System32"
				$CCMSetup = "ccmsetup\Logs\ccmsetup.log"
		

			#Uninstall Client
			Write-Host "Uninstalling SCCM Client..."
			Send-RemoteCommand -ComputerName $Name -Command "C:\Windows\$SYS\cmd.exe" -Arguements "/c $UninstallCommand"

			Write-Host "Force option: Rebuilding WMI"
			Write-Host "Stopping WMI"
			Test-Service -ServiceName SharedAccess -ComputerName $Name -Action Stop
			Test-Service -ServiceName winmgmt -ComputerName $Name -Action Stop
			Start-Sleep -Seconds 10
			Write-Host "Renaming Repository"
			$Repository = "\\$Name\c$\windows\Syswow64\wbem\Repository","\\$Name\c$\windows\system32\wbem\Repository"
			Foreach ( $Repo in $Repository ) {
				If (Test-Path $Repo) { Rename-Item -Path $Repo -NewName "Repo.Old"; Write-Host "Renamed $Repo" }
			}
			Write-Host "Restarting WMI"
			Test-Service -ServiceName winmgmt -ComputerName $Name -Action Start
			Test-Service -ServiceName SharedAccess -ComputerName $Name -Action Start
			Start-Sleep -Seconds 20

			Write-Host "CCMExec gone. re-installing..."
			Send-RemoteCommand -ComputerName $Name -NoWait -Command "C:\Windows\$SYS\cmd.exe" -Arguements "/c $InstallCommand"
			Start-Sleep -Seconds 10
			Start-Process cmtrace.exe \\$Name\c$\Windows\$CCMSetup
			While (!(Test-Path \\$Name\c$\Windows\ccm\logs\)) {
				Write-Host "Waiting for ccmexec to come online"
				Start-Sleep -Seconds 10
			}
			Start-Process \\$Name\c$\Windows\ccm\logs\
		} Else {
			$Client = [WMIClass]"\\$($Name)\root\CCM:SMS_Client"
			$Client.InvokeMethod("RepairClient","")
		}
      }

If ($PSBoundParameters.ContainsKey('ComputerName')) {
      Foreach ($Computer in $ComputerName) {
        RepairCCM-Worker -Name $Computer
      } 
	} Else {
		RepairCCM-Worker -Name $ComputerName
    }
  }
}

function Install-CCM {
<#
    .SYNOPSIS
    Attempts to install ConfigMgr client by using PSEXEC.
    
    .DESCRIPTION
    Uses PSExec to connect to a machine and run ccmsetup with USC parameters.
    
    .PARAMETER ComputerName
    The hostname of a computer where you can connect and have administrator privileges.
	
	.PARAMETER Uninstall
	Causes the client to be uninstalled.
    
   .EXAMPLE
    C:\PS>Install-CCM 9k9562s

	PsExec v1.98 - Execute processes remotely
	Copyright (C) 2001-2010 Mark Russinovich
	Sysinternals - www.sysinternals.com

	C:\Windows\SysWOW64\cmd.exe exited on 9k9562s with error code 0.
	Success
	
    .NOTES
    Author: Jesse Harris
    For: University of Sunshine Coast
    Date Created: 10 April 2012        
    ChangeLog:
    1.0 - First Release
#>
  [CmdletBinding()]

      Param(
      [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
      [string[]]$ComputerName,[Switch]$Uninstall,[Switch]$Install)
PROCESS {

      function InstallCCM-Worker {
        Param($Name)
		
           
			$InstallCommand = "\\wsp-configmgr01\SMS_SC1\Client\ccmsetup.exe /mp:wsp-configmgr01.usc.internal /forceinstall SMSSITECODE=SC1 SMSSLP=wsp-configmgr01.usc.internal DNSSUFFIX=USC.INTERNAL SMSMP=wsp-configmgr01.usc.internal"
			$UninstallCommand = "\\wsp-configmgr01\SMS_SC1\Client\ccmsetup.exe /Uninstall"
			function Send-RemoteCommand {
				Param($Command,$Arguements,$ComputerName,[Switch]$NoWait)
				If ($NoWait) { $Options = "-d" }
				psexec.exe \\$ComputerName -s "$Command" $Arguements $Options
				If ($LASTEXITCODE -eq 0) {Write-Host -ForegroundColor Green "Success" } Else {Write-Host -ForegroundColor Red "Fail"; return 1}
			}
			#Get Architechture
			If ( ( Test-Path -path \\$Name\c$\Windows\Syswow64) ) {
				$SYS = "SysWOW64"
				$CCMSetup = "ccmsetup\Logs\ccmsetup.log"
			} Else {
				$SYS = "System32"
				$CCMSetup = "ccmsetup\Logs\ccmsetup.log"
			}
            If ($Uninstall) {
			    Write-Host "Uninstalling SCCM Client..."
			    Send-RemoteCommand -ComputerName $Name -Command "C:\Windows\$SYS\cmd.exe" -Arguements "/c $UninstallCommand"
            } else {
                Send-RemoteCommand -ComputerName $Name -NoWait -Command "C:\Windows\$SYS\cmd.exe" -Arguements "/c $InstallCommand"
			    Start-Sleep -Seconds 10
			    Start-Process cmtrace.exe \\$Name\c$\Windows\$CCMSetup
			    While (!(Test-Path \\$Name\c$\Windows\ccm\logs\)) {
				    Write-Host "Waiting for ccmexec to come online"
				    Start-Sleep -Seconds 10
			    }
			    Start-Process \\$Name\c$\Windows\ccm\logs\
            }
      }

If ($PSBoundParameters.ContainsKey('ComputerName')) {
      Foreach ($Computer in $ComputerName) {
        InstallCCM-Worker -Name $Computer
      } 
	} Else {
		InstallCCM-Worker -Name $ComputerName
    }
  }
}

if (-Not (Get-Alias -Name ginv -ErrorAction SilentlyContinue)) {
    New-Alias -Name ginv -Value Get-CfgClientInventory -Scope Global
}
if (-Not (Get-Alias -Name gip -ErrorAction SilentlyContinue)) {
    New-Alias -Name gip -Value Get-CfgIPAddress -Scope Global
}

function Get-RecentMachines {
    Param($CollectionName,$AgentTimeSpan)
    
    $DaysAgo = (Get-Date).AddDays(-$AgentTimeSpan)
    Get-CfgCollectionMembers -Collection $CollectionName | `
        Get-CfgClientInventory | `
            ForEach-Object {
                $Index = [array]::IndexOf($_.AgentName,"Heartbeat Discovery")
                If (($Index -gt -1) -and ([datetime]::ParseExact($_.AgentTime[$Index],"yyyyMMddHHmmss.000000+***",$null) -gt $DaysAgo)) { 
                    $_ | Select-Object @{label='ComputerName';expression={$_.Name}},@{label='Domain';expression={$_.ResourceDomainORWorkgroup}},LastLogonUserName,IPAddresses,@{label='AgentIndex';expression={$Index}},@{label='AgentTime';expression={Get Date $_.AgentTime[$Index]}}
                }
            }
}

function Get-AdvertisementResult {
<#
    .SYNOPSIS
    Retreive Status of an/all Advertisment(s) from the SCCM primary site server for a specfic computer.
    
    .DESCRIPTION
    Connects to the primary site server and queries the WMI namespace for advertisement status.
    
    .PARAMETER AdvertID
    The ID of an Advertisment on the SCCM Site. Format example: USC20746

    .PARAMETER ComputerName
    The name of a computer to query against.
    
   .EXAMPLE
    C:\PS>Get-AdvertisementResults -ComputerName B1HM52S
    
    ComputerName      : B1HM52S
    AdvertisementID   : USC20662
    Status            : Retrying
    LastStatusTime    : 20130418230349.480000+***
    AdvertisementName : Visual3D_Reader - [Virtual application] to Application Tester User

    ComputerName      : B1HM52S
    AdvertisementID   : USC2071E
    Status            : Retrying
    LastStatusTime    : 20130418230349.450000+***
    AdvertisementName : XPanels - [Virtual application] to Crestron XPanels 1.0  USR

    .EXAMPLE
    C:\PS>Get-CfgCollectionMembers "Lab HG31" | Get-AdvertisementResults
    Command is usefull for gathering the overall success/failure of advertisements in a venue.
		
    .NOTES
    Author: Jesse Harris
    For: University of Sunshine Coast
    Date Created: 20 June 2013
    ChangeLog:
    1.0 - First Release
#>
[CmdLetBinding()]
	Param(
		[Parameter(
		ValueFromPipeline=$True,
		ValueFromPipelineByPropertyName=$true,
		Mandatory=$true)]$ComputerName,
		$AdvertID,
		$CfgSiteServer=$Global:CfgSiteServer,$CfgSiteCode=$Global:CfgSiteCode)
	Process {
		If ($ComputerName.ComputerName) {
			$Name = $ComputerName.ComputerName
		} Else {
			$Name = $ComputerName
		}

		Get-WMIObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" -Query `
			"Select ResourceID from SMS_R_System Where Name like '$Name'" | ForEach-Object {
                $ResourceID = $_.ResourceID
                If ($AdvertID) {
                    $Query = "Select AdvertisementID,LastStateName,LastStatusTime From SMS_ClientAdvertisementStatus Where ResourceID = '$ResourceID' and AdvertisementID = '$AdvertID'"
                } Else {
                    $Query = "Select AdvertisementID,LastStateName,LastStatusTime From SMS_ClientAdvertisementStatus Where ResourceID = '$ResourceID'"
                }
				$AdvObj = Get-WMIObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" -Query $Query | 
				    Select @{LABEL='ComputerName'; Expression={$Name}},AdvertisementID,@{LABEL='Status'; Expression={$_.LastStateName}},LastStatusTime 
                ForEach ($Adv in $AdvObj) {
                    $AdvID = $Adv.AdvertisementID
                    $AdvName = (Get-WMIObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" -Query "Select AdvertisementName From SMS_Advertisement Where AdvertisementID = '$AdvID'").AdvertisementName
                    $Adv | Add-Member -MemberType NoteProperty -Name AdvertisementName -Value $AdvName -PassThru
                }
			}
	}
}


function Get-MachineInventory {
<#
    .SYNOPSIS
    Retreive Inventory information of a USC computer from ActiveDirectory and Config Manager.
    
    .DESCRIPTION
    Connects to the primary site server and queries the WMI namespace for client inventory, Connects to AD and gathers group data and description.
    
    .PARAMETER ComputerName
    The name of a client computer, registered with the Site Server.
    
   .EXAMPLE
    C:\PS>Get-MachineInventory 6WMPSN1
    
	LastedLogonUserName : jpharris
    ADCreated           : 6/05/2011 1:01:47 PM
    ADPath              : usc.internal/MOEDev/DevWorkstations/Staff/6WMPSN1
    DockStatus          :
    ADIPAddress         :
    ADMemberOf          :
    OU                  : STAFF
    MonitorRes          :
    ComputerName        : 6wmpsn1
    MonitorCount        :
    Model               : Virtual Machine
    ADDescription       : M6500 - JPHarris
                          SetBy Jpharris
    WKSGROUP            :
    VLAN                : Virtual Server (Test / Dev Network)
    ADPWDLastSet        : 17/09/2012 9:17:38 AM
    LastHeartbeat       : 5/10/2012 8:52:07 AM
    Memory              : 1,606 MB
    ADOperatingSystem   : Windows 7 Enterprise
   
	.EXAMPLE
	C:\PS>Import-CSV C:\Computers.csv | ForEach-Object { Get-MachineInventory -ComputerName $_."Column A" } | Export-CSV C:\ComputerInventory.csv

    This command will get the machine inventory for each computer in the column titled "Column A" from the Computers.csv file.	

	.EXAMPLE
	C:\PS>Get-MachineInventory 6WMPSN1 | Select ComputerName,DockStatus
		Returns just the computername and dockstatus properties
	
	.EXAMPLE
	C:\PS>Get-CfgCollectionMembers -Collection "Latitude E Series" | Get-MachineInventory
		Returns the machine inventory for all computers in the SCCM collection "Latitude E Series"
		
    .NOTES
    Author: Jesse Harris
    For: University of Sunshine Coast
    Date Created: 05 Oct 2012        
    ChangeLog:
    1.0 - First Release
#>
    [CmdLetBinding()]
	Param(
		[Parameter(
		ValueFromPipeline=$True,
		ValueFromPipelineByPropertyName=$true,
		Mandatory=$true)]$ComputerName,
		$AdvertID,
		$CfgSiteServer=$Global:CfgSiteServer,$CfgSiteCode=$Global:CfgSiteCode)

    Begin {
        #Check if SCCM Module is available and loaded
        #Write-Host -ForegroundColor Cyan "Checking modules..."
        $Modules = "ActiveDirectory","USC-SCCM","USC-DellWarranty","Import-Excel","USC-VLAN"
        ForEach ($Module in $Modules) {
            If (!(Get-Module -Name $Module)) {
                If (Get-Module -ListAvailable | Where-Object {$_.Name -eq $Module}) {
                    Write-Host -ForegroundColor Cyan "Loading $Module module..."
                    Import-Module $Module
                } Else {
                    Write-Host -ForegroundColor Red "$Module module not available"
                    Return 1
                }
            }
        }
    }

	Process {

        function Get-MachineInventoryWorker {
            Param($Name)
            If ($SCCMInventory = Get-CfgClientInventory -ComputerName $Name -Properties Monitor,Model,Memory) {
                $SCCMInventory.SystemGroupName | Where-Object {(($_ -notmatch "SCCM") -and ($_ -notmatch "Domain Computers")) -or ($_ -match "MGSProd WKS")} | 
                    ForEach-Object {$WKSGroup += $($_ -replace "USC\\*","") + " "}
                $Index = [array]::IndexOf($SCCMInventory.AgentName,"Heartbeat Discovery")
                If ($Index -gt -1) {
                    $HeartBeatDate = [datetime]::ParseExact($SCCMInventory.AgentTime[$Index],"yyyyMMddHHmmss.000000+***",$null)
                }
            }
            If ($ADInventory = Get-ADComputer -Identity $Name -Properties MemberOf,Description,Created,CanonicalName,PasswordLastSet,OperatingSystem,IPv4Address) {
                $ADInventory.MemberOf | Where-Object {($_ -notmatch "SCCM")} | ForEach-Object {$ADGroups += $($_) + " "}
            }
            If ($SCCMInventory.LastLogonUserName) { $ADUser = Get-ADUser -Identity $SCCMInventory.LastLogonUserName -Properties ExtensionAttribute14,mail,DistinguishedName,memberof }

            New-Object -TypeName PSObject -Property @{
                'ComputerName' = $Name
                'MonitorCount' = $SCCMInventory.MonitorCount
                'MonitorRes' = $SCCMInventory.MonitorRes
                'Memory' = $SCCMInventory.Memory
                'LastLogonUserName' = $SCCMInventory.LastLogonUserName
                'LastHeartbeat' = $HeartBeatDate
                'WarrantyEndDate' = (Get-DellWarrantyStatus -ComputerName $Name).WarrantyEndDate
                'OU' = $SCCMInventory.SystemOUName[$SCCMInventory.SystemOUName.Count-1] -replace ".*/",""
                'WKSGROUP' = $WKSGroup
                'Model' = $SCCMInventory.Model
                'ADMemberOf' = $ADGroups
                'ADDescription' = $ADInventory.Description
                'ADCreated' = $ADInventory.Created
                'ADPath' = $ADInventory.CAnonicalName
                'ADPWDLastSet' = $ADInventory.PasswordLastSet
                'ADOperatingSystem' = $ADInventory.OperatingSystem
                'ADIPAddress' = $ADInventory.IPv4Address
                'VLAN' = (Get-VLANFromIPAddress -IPAddress $ADInventory.IPv4Address)
                'UserExtensionAttribute14' = $ADUser.Extensionattribute14
                'UserMail' = $ADUser.mail
                'UserPath' = $ADUser.DistinguishedName
                'UserGroupMembers' = $ADUser.memberof
            }
        }
        If ($PSBoundParameters.ContainsKey('ComputerName')) {
            Foreach ($Computer in $ComputerName) {
                If ($Computer.ComputerName) {
                    Get-MachineInventoryWorker -Name $Computer.ComputerName
                } Else {
                    Get-MachineInventoryWorker -Name $Computer
                }
            }
	    } Else {
            Get-MachineInventoryWorker -Name $ComputerName
        }
    }
}

function Get-AdvertisementStatus {
<#
    .SYNOPSIS
    Retreive Status of an Advertisment from the SCCM primary site server.
    
    .DESCRIPTION
    Connects to the primary site server and queries the WMI namespace for advertisement status.
    
    .PARAMETER AdvertID
    The ID of an Advertisment on the SCCM Site. Format example: USC20746
    
   .EXAMPLE
    C:\PS>Get-AdvertisementStatus USC20746
    
	ComputerName                                                LastStateName
    ------------                                                -------------
    8KLF6R1                                                     Retrying
    7QNQ12S                                                     Failed
    GBRS62S                                                     Failed
    4K9562S                                                     Failed
    HCQ6FS1                                                     Failed
    4WHNBS1                                                     Failed
    DTT5D2S                                                     Failed
   
	.EXAMPLE
	C:\PS>Import-CSV C:\Computers.csv | ForEach-Object { Get-MachineInventory -ComputerName $_."Column A" } | Export-CSV C:\ComputerInventory.csv

    This command will get the machine inventory for each computer in the column titled "Column A" from the Computers.csv file.	

	.EXAMPLE
	C:\PS>Get-MachineInventory 6WMPSN1 | Select ComputerName,DockStatus
		Returns just the computername and dockstatus properties
	
	.EXAMPLE
	C:\PS>Get-CfgCollectionMembers -Collection "Latitude E Series" | Get-MachineInventory
		Returns the machine inventory for all computers in the SCCM collection "Latitude E Series"
		
    .NOTES
    Author: Jesse Harris
    For: University of Sunshine Coast
    Date Created: 05 Oct 2012        
    ChangeLog:
    1.0 - First Release
#>
[CmdLetBinding()]
	Param(
		[Parameter(
		ValueFromPipeline=$True,
		ValueFromPipelineByPropertyName=$true,
		Mandatory=$true)]$AdvertID="USC20746",
		$CfgSiteServer=$Global:CfgSiteServer,$CfgSiteCode=$Global:CfgSiteCode,$State)
	Process {
            switch ($State) {
                Failed {
                    $Query = "Select ResourceID,LastStateName From SMS_ClientAdvertisementStatus Where AdvertisementID = '$AdvertID' and LastStateName = 'Failed'"
                    }
                Succeeded {
                    $Query = "Select ResourceID,LastStateName From SMS_ClientAdvertisementStatus Where AdvertisementID = '$AdvertID' and LastStateName = 'Succeeded'"
                    }
                NoStatus {
                    $Query = "Select ResourceID,LastStateName From SMS_ClientAdvertisementStatus Where AdvertisementID = '$AdvertID' and LastStateName = 'No Status'"
                    }
                Accepted {
                    $Query = "Select ResourceID,LastStateName From SMS_ClientAdvertisementStatus Where AdvertisementID = '$AdvertID' and LastStateName LIKE 'Accepted%'"
                    }
                default {
                    $Query = "Select ResourceID,LastStateName From SMS_ClientAdvertisementStatus Where AdvertisementID = '$AdvertID'"
                }
            }

	    	
            Get-WMIObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" -Query $Query |
                Select @{LABEL='ComputerName'; Expression={$Resource = $_.ResourceID; (Get-WMIObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$($CfgSiteCode)" -Query "Select Name from SMS_R_System Where ResourceID = '$Resource'").Name}},LastStateName
    }
}

function Get-CurrentUser {
	Param(
		[Parameter(
	        	ValueFromPipeLine = $true,
	                ValueFromPipelinebyPropertyName = $True)]
		$ComputerName=$env:ComputerName)
	Process {
		If ($ComputerName.ComputerName) {
			$Computers = $ComputerName.ComputerName
		} Else {
			$Computers = $ComputerName
		}
		Foreach ($ComputerName in $Computers) {
			If (Test-Connection -ComputerName $ComputerName -Quiet -Count 1 -TTL 5) {
				Get-WmiObject -ComputerName $ComputerName -Class Win32_computersystem | 
					Select -Property @{label='UserName'; expression={$_.UserName.TrimStart("USC\")}},@{label='ComputerName';expression={$ComputerName}}
			}
		}
	}
}

function Invoke-CfgConfigEval {
<#
    .SYNOPSIS
    Evaluate Configuration baslines assigned to a configuration manager client.
    
    .DESCRIPTION
    Connects to a client machine WMI namespace and executes a method on a named configuration item or all configuration itmes.
    
    .PARAMETER ComputerName
    The name of a client computer, with Configuration Manager client installed.
    
   .EXAMPLE
    C:\PS>Invoke-CfgConfigEval D8MN52S
    
    __GENUS          : 1
    __CLASS          : __PARAMETERS
    __SUPERCLASS     :
    __DYNASTY        : __PARAMETERS
    __RELPATH        : __PARAMETERS
    __PROPERTY_COUNT : 2
    __DERIVATION     : {}
    __SERVER         : D8MN52S
    __NAMESPACE      : ROOT\ccm\dcm
    __PATH           : \\D8MN52S\ROOT\ccm\dcm:__PARAMETERS
    JobId            : {12BF6F7D-B533-4361-83C3-6B407F07A83F}
    ReturnValue      : 0
    PSComputerName   : D8MN52S
   
	.EXAMPLE
	C:\PS>Get-CfgCollectionMembers "Lab H107" | Invoke-CfgConfigEval

    This command will retrieve all members of the collection "Lab H107" and attempt to connect to each machines WMI to evaluation configuration baselines.

	.EXAMPLE
	C:\PS>Invoke-CfgConfigEval -ComputerName BSYQXY1 -Name Application-Shortcut-NVR
		Attempts to evaluate only baseline "Application-Shortcut-NVR"
		
    .NOTES
    Author: Jesse Harris
    For: University of Sunshine Coast
    Date Created: 01 May 2014
    ChangeLog:
    1.0 - First Release
#>
    Param([Parameter(
		ValueFromPipeline=$True,
		ValueFromPipelineByPropertyName=$true,
		Mandatory=$true)]$ComputerName=$env:COMPUTERNAME,
        [Parameter(
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]$DisplayName)

    Process {
        function Config-Worker {
        Param($Computer)
            
            If ($DisplayName.DisplayName) {
                $DisplayName = $DisplayName.DisplayName
            }
            $DCMTrigger = [WMIClass]"\\$Computer\Root\CCM\DCM:SMS_DesiredConfiguration"
            If ($DisplayName) {
                $Query = 'Select * from SMS_DesiredConfiguration where DisplayName = "' + $DisplayName + '"'
            } Else {
                $Query = 'Select * from SMS_DesiredConfiguration'
            }

            $Configurations = Get-WmiObject -ComputerName $Computer -Namespace Root\CCM\DCM -Query $Query
            ForEach ($Config in $Configurations) {
            $Config.Name
            $Config.Version
                $DCMTrigger.TriggerEvaluation($Config.Name,$Config.Version)
            }
        }

        If ($PSBoundParameters.ContainsKey('ComputerName')) {
            Foreach ($Computer in $ComputerName) {
                If ($Computer.ComputerName) {
                    Config-Worker -Computer $Computer.ComputerName
                } Else {
                    Config-Worker -Computer $Computer
                }
            }
	    } Else {
            Config-Worker -Computer $ComputerName
        }
    }
}

function Get-CfgConfigEval {
<#
    .SYNOPSIS
    Get Configuration baselines assigned to a configuration manager client.
    
    .DESCRIPTION
    Connects to a client machine WMI namespace and retreives a configuration item or all configuration itmes.
    
    .PARAMETER ComputerName
    The name of a client computer, with Configuration Manager client installed.

    .PARAMETER DisplayName
    The Displayname of a configuration item
    
   .EXAMPLE
    C:\PS>Get-CfgConfigEval D8MN52S
    
    ComputerName         : DCG2GY1
    DisplayName          : Application-Setting-Flash AutoUpdateDisable
    IsMachineTarget      : True
    LastEvalTime         : 3/06/2014 12:39:59 AM
    LastComplianceStatus : 1
    Status               : 0
    Version              : 4

    ComputerName         : DCG2GY1
    DisplayName          : Application-Presence-Adobe Acrobat 10
    IsMachineTarget      : True
    LastEvalTime         : 3/06/2014 12:48:18 AM
    LastComplianceStatus : 1
    Status               : 0
    Version              : 2

	.EXAMPLE
	C:\PS>Get-CfgCollectionMembers "Lab H107" | Get-CfgConfigEval

    This command will retrieve all members of the collection "Lab H107" and attempt to connect to each machines WMI to list configuration baselines.

	.EXAMPLE
	C:\PS>Get-CfgConfigEval -ComputerName BSYQXY1 -DisplayName Application-Shortcut-NVR
		Attempts to list only baseline "Application-Shortcut-NVR"
		
    .NOTES
    Author: Jesse Harris
    For: University of Sunshine Coast
    Date Created: 06 June 2014
    ChangeLog:
    1.0 - First Release
#>
    Param([Parameter(
		ValueFromPipeline=$True,
		ValueFromPipelineByPropertyName=$true,
		Mandatory=$true)]$ComputerName=$env:COMPUTERNAME,$DisplayName)

    Process {
        function Config-Worker {
        Param($Computer)
            If ($DisplayName) {
                $Qeury = "Select * from SMS_DesiredConfiguration where DisplayName = ""$DisplayName"""
            } Else {
                $Qeury = "Select * from SMS_DesiredConfiguration"
            }
            Get-WmiObject -ComputerName $Computer -Namespace Root\CCM\DCM -Query $Qeury | 
                ForEach-Object {
                    Switch ($_.LastComplianceStatus) {
                        0 {$LastComplianceStatus = 'Non-Compliant'}
                        1 {$LastComplianceStatus = 'Compliant'}
                        Default {$LastComplianceStatus = 'Error'}
                    }
                    [pscustomobject]@{
                        'ComputerName' = $_.PSComputerName
                        'DisplayName' = $_.DisplayName
                        'IsMachineTarget' = $_.IsMachineTarget
                        'LastEvalTime' = If ($_.LastEvalTime) {
                            #[datetime]::ParseExact($_.LastEvalTime,'yyyyMMddHHmmss.000000+000',$null)
                            $_.ConvertToDateTime($_.LastEvalTime)                    
                        } Else {
                            $null
                        }
                        'LastComplianceStatus' = $LastComplianceStatus
                        'Status' = $_.Status
                        'Version' = $_.Version
                    }
                }
        }

        If ($PSBoundParameters.ContainsKey('ComputerName')) {
            Foreach ($Computer in $ComputerName) {
                If ($Computer.ComputerName) {
                    Config-Worker -Computer $Computer.ComputerName
                } Else {
                    Config-Worker -Computer $Computer
                }
            }
	    } Else {
            Config-Worker -Computer $ComputerName
        }
    }
}

function Get-CfgCollectionsByFolder {
<#
    .SYNOPSIS
    Get Collections based on their administrative assigned folder.
    
    .DESCRIPTION
    Connects to the primary site server, and returns collections which are contained in a folder.
    
    .PARAMETER FolderName
    The name of a folder containing device collections.

    .PARAMETER SiteServer
    The hostname of the primary site server.
    
   .EXAMPLE
    C:\PS>Get-CfgCollectionsByFolder -FolderName 'Software Distribution'
    
    FolderName            CollectionName                                         CollectionID LimitingCollection
    ----------            --------------                                         ------------ ------------------
    Software Distribution Adobe Presenter 8 MSI WKS-Install                      SC100014     All Systems
    Software Distribution Adobe Presenter 8 MSI WKS-Uninstall                    SC100015     All Systems
    Software Distribution ClimSystems TrainClim 2.0.0.31 MSI WKS                 SC100019     All Systems
    Software Distribution ClimSystems TrainClim 2.0.0.31 MSI WKS-Install         SC10001A     ClimSystems TrainClim 2.0.0.31 MS..
    Software Distribution ClimSystems TrainClim 2.0.0.31 MSI WKS-Uninstall       SC10001B     All Systems
    Software Distribution Google Google Chrome 23.0.1271.97 MSI WKS              SC10001C     All Systems
    Software Distribution Google Google Chrome 23.0.1271.97 MSI WKS-Install      SC10001D     Google Google Chrome 23.0.1271.97..
	
    .EXAMPLE
	C:\PS>Get-CfgCollectionsByFolder -FolderName 'Software Distribution' | ? LimitingCollection -eq "All USC Managed Computers" | %{Set-CMDeviceCollection -CollectionId $_.CollectionID -LimitToCollectionID SC100030

    This command will retrieve all collections under the 'Software Distribution' folder which are currently limited to collection name 'All USC Managed Computers' and limit them to 'All USC Non-Volatile Computers'
		
    .EXAMPLE
    C:\PS>Get-CfgCollectionsByFolder -FolderName 'Software Distribution' -UserCollection

    This command will retrieve user collections by user foldername.

    .NOTES
    Some of the examples in this help, depend on the official Configuration Manager module
    Author: Jesse Harris
    For: University of Sunshine Coast
    Date Created: 17 May 2016
    ChangeLog:
    1.0 - First Release
#>
[CmdLetBinding()]
Param([Parameter(Mandatory=$True)]$FolderName,$CfgSiteServer=$Global:CfgSiteServer,$CfgSiteCode=$Global:CfgSiteCode,[switch]$UserCollection)
    
    If ($UserCollection) {
        $objectType = 'SMS_Collection_User'
    } Else {
        $objectType = 'SMS_Collection_Device'
    }

    $InstanceKey = Get-WmiObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_SC1" -Query "Select * from SMS_ObjectContainerNode Where objectTypeName = '$objectType'" | Where-Object {$_.Name -eq $FolderName}
    If (-Not $InstanceKey) {
        Write-Error -Category ObjectNotFound -Message "No Configuration manager folder named $FolderName could be found"
        return
    }


    Get-WmiObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$CfgSiteCode" -Query "select * from SMS_ObjectContainerItem where ContainerNodeID = '$($InstanceKey.ContainerNodeID)'" | ForEach-Object {
        Get-WmiObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$CfgSiteCode" -Query "select * from SMS_Collection where CollectionID = ""$($_.InstanceKey)"""} | %{
            [PSCustomObject]@{
                'FolderName' = $FolderName; 
                'CollectionName' = $_.Name;
                'CollectionID' = $_.CollectionID
                'LimitingCollection' = $_.LimitToCollectionName
            }
        }
}

function Get-CfgCollectionsDeps {
<#
    .SYNOPSIS
    Get a list of collections which are limited to a specific collection.
    
    .DESCRIPTION
    Connects to the primary site server WMI namespace and retreives a values from SMS_CollectionDependancies.
    
    .PARAMETER CollectionName
    The name of a source collection to which other collections are limited to.

    .PARAMETER SiteServer
    The hostname of the primary site server
    
   .EXAMPLE
    C:\PS>Get-CfgCollectionsDeps 'All USC Managed Computers'
    
    SourceCollectionID DependentCollectionID
    ------------------ ---------------------
    SC10025C           SC100030
    SC10025C           SC100413
    SC10025C           SC100414
    SC10025C           SC100444
    SC10025C           SC100500
    SC10025C           SC10051C

	.EXAMPLE
	C:\PS>Get-CfgCollectionDeps "All USC Managed Computers" | ForEach-Object {Set-CMDeviceCollection -Id $_.DependentCollectionID -LimitToCollectionId SC100030 -WhatIf}

    This command will update the limiting collection of all collections currently limited to 'All USC Managed Computers'
    		
    .NOTES
    Author: Jesse Harris
    For: University of Sunshine Coast
    Date Created: 17 May 2016
    ChangeLog:
    1.0 - First Release
#>
[CmdLetBinding()]
Param([Parameter(Mandatory=$True)]$CollectionName,$CfgSiteServer=$Global:CfgSiteServer,$CfgSiteCode=$Global:CfgSiteCode)
    
    $CollectionID = (Get-WmiObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_$CfgSiteCode" -Query "Select CollectionID from SMS_Collection Where Name = '$CollectionName'").CollectionID
    If (-Not $CollectionID) {
        Write-Error -Category ObjectNotFound -Message "No  collection with name $CollectionName could be found"
        return
    }
    $CollectionDeps = Get-WmiObject -ComputerName $CfgSiteServer -Namespace "root\sms\site_SC1" -Query "select * from SMS_CollectionDependencies where SourceCollectionID='$CollectionID'"
    If (-Not $CollectionDeps) {
        Write-Error -Category ObjectNotFound -Message "No collection references of $CollectionName could be found"
        return
    }

    #Select distinct SourceCollectionID, DependentCollectionID from SMS_CollectionDependencies where SourceCollectionID='SC10047B'

    $CollectionDeps | Select SourceCollectionID,DependentCollectionID
}

function Invoke-CfgStateMessageSend {
    [CmdLetBinding()]
    Param($ComputerName)
    Begin{}
    Process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $CCMObject = New-Object -ComObject Microsoft.CCM.UpdatesStore
            $CCMObject.RefreshServerComplianceState()
        }
    }
}

function Set-CfgService {
    [CmdLetBinding()]
    Param($ComputerName=$env:ComputerName,$Name,
    $Previous)
    
    Switch ($Name) {
        rw {$s = 'WinRM'}
        rr {$s = 'RemoteRegistry'}
        cm {$s = 'CCMExec'}
        Default {$s = $Name}
    }

    $Result = $null
    $Svc = Get-Service -ComputerName $ComputerName -Name $s
    If ($Previous -eq 'Disabled') {
            $Svc | Stop-Service
            $Svc | Set-Service -StartUpType 'Disabled'
    ElseIf ($Previous -eq 'Stopped') {
            $Svc | Stop-Service
        }
    } Else {
        Switch ($Svc.Status) {
            'Running' {$Svc | Restart-Service}
            'Stopped' {If ($Svc.StartType -eq 'Disabled') {$Result='Disabled'; $Svc | Set-Service -StartUpType Manual} Else {$Result='Stopped'}; $Svc | Start-Service}
            Default {}
        }
    }
    return $Result
}