# Processes
function Get-WmiProcess 
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            Get-WmiObject win32_Process | Select CSName, Name, ProcessID, 
            @{name='ParentProcessName'; expression={(Get-Process -id $_.ParentProcessId).Name}}, 
            ParentProcessID, HandleCount, ThreadCount, Path, CommandLine            
                              
        }
    }
} 

<# Example

$ComputerName = 'localhost'
$Credential = Get-Credential

$processes = Get-WmiProcess -ComputerName $ComputerName -Credential $Credential

$csvFilePath = ($env:USERPROFILE + "\Desktop\processes.csv")
$csvContent = $processes | ConvertTo-Csv -NoTypeInformation
$csvContent | Out-File -FilePath $csvFilePath -Encoding UTF8 -Noclobber
#>

# Services
function Get-ServiceInfo
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
        Get-CimInstance -Class Win32_Service | Select Name,State,SystemName, DisplayName,Description,PathName,InstallDate, ProcessId,
        @{n='ProcessName';e={(Get-WmiObject -Class Win32_Process -Filter "ProcessId='$($_.ProcessId)'").Name}}, 
        @{n='ParentProcessID';e={(Get-WmiObject -Class Win32_Process -Filter "ProcessId='$($_.ProcessId)'").ParentProcessID}},
        @{n='ParentProcessName';e={(Get-Process -ID (Get-WmiObject -Class Win32_Process -Filter "ProcessId='$($_.ProcessId)'").ParentProcessID).Name}},
        StartMode,ExitCode,DelayedAutoStart
            
        }                          
                                 
    }
} 

<# Example

$ComputerName = 'localhost'
$Credential = Get-Credential

$services = Get-ServiceInfo -ComputerName $ComputerName -Credential $Credential

$csvFilePath = ($env:USERPROFILE + "\Desktop\services.csv")
$csvContent = $services | ConvertTo-Csv -NoTypeInformation
$csvContent | Out-File -FilePath $csvFilePath -Encoding UTF8 -Noclobber

#>


# Connections
function Get-Connection {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$true)]
        [String[]]
        $ComputerName,

        [PSCredential]
        $Credential
    )

    Begin {
        If (!$Credential) {
            $Credential = Get-Credential
        }
    }

    Process {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $processes = Get-CimInstance Win32_Process
            $connections = Get-NetTCPConnection -State Established

            $connections | ForEach-Object {
                $connection = $_
                $process = $processes | Where-Object { $_.ProcessID -eq $connection.OwningProcess }
                $parentProcessID = $process.ParentProcessID
                $parentProcess = $processes | Where-Object { $_.ProcessID -eq $parentProcessID }

                [PSCustomObject]@{
                    LocalAddress     = $connection.LocalAddress
                    LocalPort        = $connection.LocalPort
                    RemoteAddress    = $connection.RemoteAddress
                    RemotePort       = $connection.RemotePort
                    State            = $connection.State
                    OwningProcess    = $connection.OwningProcess
                    Process          = $process.Name
                    ParentProcessID  = $parentProcess.ProcessID
                    ParentProcess    = $parentProcess.Name
                    CreationTime     = $connection.CreationTime
                }
            }
        }
    }
}


<# Example

$ComputerName = 'localhost'
$Credential = Get-Credential

$connections = Get-Connection -ComputerName $ComputerName -Credential $Credential

$csvFilePath = ($env:USERPROFILE + "\Desktop\connections.csv")
$csvContent = $connections | ConvertTo-Csv -NoTypeInformation
$csvContent | Out-File -FilePath $csvFilePath -Encoding UTF8 -Noclobber
#>


# Scheduled Tasks
function Get-SchTask
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock { 
            $schtasks = (Get-ScheduledTask)
                foreach ($task in $schtasks)
                {
	                $taskinfo=Get-ScheduledTaskInfo -TaskPath $task.TaskPath -TaskName $task.TaskName
	                [PSCustomObject]@{
		                TaskName = $task.TaskName
		                Author   = $task.Author
		                Date     = $task.Date
		                URI      = $task.URI
		                State    = $task.State
		                TaskPath = $task.TaskPath
		                LastRunTime = $taskinfo.LastRunTime
		                LastTaskResult = $taskinfo.LastTaskResult
		                NextRunTime    = $taskinfo.NextRunTime
                       }

                }
            
        }
    }    
} 

<# Example

$ComputerName = 'localhost'
$Credential = Get-Credential

$schtasks = Get-SchTask -ComputerName $ComputerName -Credential $Credential

$csvFilePath = ($env:USERPROFILE + "\Desktop\schtasks.csv")
$csvContent = $schtasks | ConvertTo-Csv -NoTypeInformation
$csvContent | Out-File -FilePath $csvFilePath -Encoding UTF8 -Noclobber
#>


# Prefetch
function Get-Prefetch 
{
    [cmdletbinding()]
    Param
    (
        [Parameter()]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {   
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $pfconf = (Get-ItemProperty "hklm:\system\currentcontrolset\control\session manager\memory management\prefetchparameters").EnablePrefetcher 

            Switch -Regex ($pfconf) {
                "[1-3]" {
                    $o = "" | Select-Object FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc
                    ls $env:windir\Prefetch\*.pf | % {
                        $o.FullName = $_.FullName;
                        $o.CreationTimeUtc = Get-Date($_.CreationTimeUtc) -format o;
                        $o.LastAccesstimeUtc = Get-Date($_.LastAccessTimeUtc) -format o;
                        $o.LastWriteTimeUtc = Get-Date($_.LastWriteTimeUtc) -format o;
                        $o }
                         }
            default {
                Write-Output "Prefetch not enabled on ${env:COMPUTERNAME}."
                    }
            }
        } 

    }
}

<# Example

$ComputerName = 'localhost'
$Credential = Get-Credential

$prefetch = Get-Prefetch -ComputerName $ComputerName -Credential $Credential


$csvFilePath = ($env:USERPROFILE + "\Desktop\prefetch.csv")
$csvContent = $prefetch | ConvertTo-Csv -NoTypeInformation
$csvContent | Out-File -FilePath $csvFilePath -Encoding UTF8 -Noclobber
#>


# OS Information
function Get-OSInfo 
{
    [cmdletbinding()]
    Param
    (
        [Parameter()]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {Get-CimInstance -ClassName Win32_OperatingSystem}
    }
}

<# Example

$ComputerName = 'localhost'
$Credential = Get-Credential

$os_info = Get-OSInfo -ComputerName $ComputerName -Credential $Credential

$csvFilePath = ($env:USERPROFILE + "\Desktop\os_info.csv")
$csvContent = $os_info | ConvertTo-Csv -NoTypeInformation
$csvContent | Out-File -FilePath $csvFilePath -Encoding UTF8 -Noclobber

#>


# Registry Run Keys
function Get-RegistryRun {
    [CmdletBinding()]
    param (
        [Parameter()]
        [PSCustomObject]$RegList,

        [String[]]$ComputerName,

        [PSCredential]$Credential
    )

    Begin {
        if (!$Credential) {
            $Credential = Get-Credential
        }
    }

    Process {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $reg_array = @(
                [PSCustomObject]@{
                    Key = "HKCU:\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"
                    Description = "This key contains the list of programs that are configured to run when the current user logs in"
                },
                [PSCustomObject]@{
                    Key = "HKCU:\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce"
                    Description = "This key contains the list of programs that are configured to run once when the current user logs in"
                },
                [PSCustomObject]@{
                    Key = "HKLM:\HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
                    Description = "This key contains the list of programs that are configured to run when any user logs in"
                },
                [PSCustomObject]@{
                    Key = "HKLM:\HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce"
                    Description = "This key contains the list of programs that are configured to run once when any user logs in"
                },
                [PSCustomObject]@{
                    Key = "HKCU:\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
                    Description = "This key stores the paths to special folders for the current user, such as the Desktop, Start Menu, and Favorites"
                },
                [PSCustomObject]@{
                    Key = "HKCU:\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
                    Description = "This key stores the paths to common shell folders for the current user"
                },
                [PSCustomObject]@{
                    Key = "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
                    Description = "This key stores the paths to common shell folders for all users on the machine"
                },
                [PSCustomObject]@{
                    Key = "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
                    Description = "This key stores the paths to special folders for all users on the machine"
                },
                [PSCustomObject]@{
                    Key = "HKLM:\HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
                    Description = "This key contains the list of services that are configured to run once when the system starts"
                },
                [PSCustomObject]@{
                    Key = "HKCU:\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
                    Description = "This key contains the list of services that are configured to run once when the user logs in"
                },
                [PSCustomObject]@{
                    Key = "HKLM:\HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices"
                    Description = "This key contains the list of services that are configured to run when the system starts"
                },
                [PSCustomObject]@{
                    Key = "HKCU:\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices"
                    Description = "This key contains the list of services that are configured to run when the user logs in"
                }
            )

            foreach ($key in $reg_array) {
                if (Test-Path -Path $key.Key) {
                    $RegistryKey = Get-Item -Path $key.Key
                    $Values = $RegistryKey.GetValueNames() | ForEach-Object {
                        [PSCustomObject]@{
                            Name = $_
                            Data = $RegistryKey.GetValue($_)
                        }
                    }

                    [PSCustomObject]@{
                        Key = $key.Key
                        Description = $key.Description
                        Values = $Values
                        Name = $Values.Name
                        Data = $Values.Data
                    }
                }
            }
        }
    }
}

<# Example

$ComputerName = 'localhost'
$Credential = Get-Credential

$reg_run = Get-RegistryRun -ComputerName $ComputerName -Credential $Credential

$csvFilePath = ($env:USERPROFILE + "\Desktop\reg_run.csv")
$csvContent = $reg_run | ConvertTo-Csv -NoTypeInformation
$csvContent | Out-File -FilePath $csvFilePath -Encoding UTF8 -Noclobber
#>


# Startup Folders
function Get-StartupFolders
{
    [cmdletbinding()]
    Param
    (
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )

    Begin
    {
        If (!$Credential) { $Credential = Get-Credential }
    }

    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $startupFolders = @(
                @{
                    Path = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
                    Description = "User Startup Folder"
                }
                @{
                    Path = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
                    Description = "All Users Startup Folder"
                }
            )

            foreach ($folder in $startupFolders)
            {
                if (Test-Path -Path $folder.Path -PathType Container)
                {
                    $items = Get-ChildItem -Path $folder.Path -File

                    if ($items)
                    {
                        $items | ForEach-Object {
                            $file = $_
                            $fileInfo = $file | Get-Item

                            [PSCustomObject]@{
                                Path = $folder.Path
                                Description = $folder.Description
                                Name = $fileInfo.Name
                                Size = $fileInfo.Length
                                LastWriteTime = $fileInfo.LastWriteTime
                            }
                        }
                    }
                }
            }
        }
    }
}

<# Example

$ComputerName = 'localhost'
$Credential = Get-Credential

$startup_folders = Get-StartupFolders -ComputerName $ComputerName -Credential $Credential

$csvFilePath = ($env:USERPROFILE + "\Desktop\startup_folders.csv")
$csvContent = $startup_folders | ConvertTo-Csv -NoTypeInformation
$csvContent | Out-File -FilePath $csvFilePath -Encoding UTF8 -Noclobber
#>

# Local Users
function Get-LUser
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock { 
            Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'"
           
        }
        
    } 
} 

<# Example

$ComputerName = 'localhost'
$Credential = Get-Credential

$local_users = Get-LUser -ComputerName $ComputerName -Credential $Credential

$csvFilePath = ($env:USERPROFILE + "\Desktop\local_users.csv")
$csvContent = $local_users | ConvertTo-Csv -NoTypeInformation
$csvContent | Out-File -FilePath $csvFilePath -Encoding UTF8 -Noclobber

#>

# Local Groups
function Get-LGroup
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            Get-WmiObject -Class Win32_Group  
        }
    }    
} 

<# Example

$ComputerName = 'localhost'
$Credential = Get-Credential

$local_groups = Get-LGroup -ComputerName $ComputerName -Credential $Credential

$csvFilePath = ($env:USERPROFILE + "\Desktop\local_groups.csv")
$csvContent = $local_groups | ConvertTo-Csv -NoTypeInformation
$csvContent | Out-File -FilePath $csvFilePath -Encoding UTF8 -Noclobber

#>

# Local Group Members
function Get-LGroupMembers
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            try
            {foreach ($name in (Get-WmiObject -Class Win32_Group).Name) {
             [PSCustomObject]@{
             GroupName = $name 
             Member    = (Get-LocalGroupMember $name)}                                   
             }}
      
            catch
            {foreach ($name in (Get-WmiObject -Class Win32_Group).Name) {
             [PSCustomObject]@{
             GroupName = $name 
             Member    = Get-WmiObject win32_groupuser | Where-Object {$_.groupcomponent -like "*$name*"} | ForEach-Object {  
             $_.partcomponent –match ".+Domain\=(.+)\,Name\=(.+)$" > $null  
             $matches[1].trim('"') + "\" + $matches[2].trim('"')  
             }  
   
             }
             }}
        }
        
    } 
} 
<# Example

$ComputerName = 'localhost'
$Credential = Get-Credential

$local_group_members = Get-LGroupMembers -ComputerName $ComputerName -Credential $Credential

$csvFilePath = ($env:USERPROFILE + "\Desktop\local_groups_members.csv")
$csvContent = $local_group_members | ConvertTo-Csv -NoTypeInformation
$csvContent | Out-File -FilePath $csvFilePath -Encoding UTF8 -Noclobber
#>

# Shares
function Get-ShareInfo
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            foreach ($share in (Get-SmbShare).Name) {Get-SmbShareAccess $share} 
        }
    }    
} 

<# Example

$ComputerName = 'localhost'
$Credential = Get-Credential

$shares = Get-ShareInfo -ComputerName $ComputerName -Credential $Credential

$csvFilePath = ($env:USERPROFILE + "\Desktop\shares.csv")
$csvContent = $shares | ConvertTo-Csv -NoTypeInformation
$csvContent | Out-File -FilePath $csvFilePath -Encoding UTF8 -Noclobber
#>

# Logon History
function Get-LogOnHistory
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $loggedOnUsers = Get-WmiObject win32_loggedonuser
            $sessions = Get-WmiObject win32_logonsession
            $logons = @()

            foreach ($user in $loggedOnUsers)
            {
                $user.Antecedent -match '.+Domain="(.+)",Name="(.+)"$' > $nul
                $domain = $matches[1]
                $username = $matches[2]
    
                $user.Dependent -match '.+LogonId="(\d+)"$' > $nul
                $LogonId = $matches[1]

                $logons += [PSCustomObject]@{
                    Domain  = $domain
                    User    = $username
                    LogonId = $LogonId
                }    
            }

            $logonDetail = foreach ($session in $sessions)
            {
                $logonType = switch ($session.LogonType)
                {
                    2 { "Network" }
                    3 { "Batch" }
                    4 { "Service" }
                    5 { "Unlock" }
                    7 { "Unlock (Cleartext)" }
                    8 { "Remote Interactive" }
                    9 { "Cached Interactive" }
                    Default { "Unknown" }
                }

                [PSCustomObject]@{
                    LogonId     = $session.LogonId
                    LogonTypeId = $session.LogonType
                    LogonType   = $logonType
                    Domain      = ($logons | Where-Object { $_.LogonId -eq $session.LogonId }).Domain
                    User        = ($logons | Where-Object { $_.LogonId -eq $session.LogonId }).User
                    StartTime   = $session.StartTime
                }
            }

            $logonDetail
        }
    }    
}

<# Example
$ComputerName = "localhost"
$Credential = Get-Credential

$logon_history = Get-LogOnHistory -ComputerName $ComputerName -Credential $Credential | Select PSComputerName, LogonId, LogonTypeId, LogonType, Domain, User, StartTime

$csvFilePath = ($env:USERPROFILE + "\Desktop\logon_history.csv")
$csvContent = $logon_history | ConvertTo-Csv -NoTypeInformation
$csvContent | Out-File -FilePath $csvFilePath -Encoding UTF8 -Noclobber
#>

#>


# Exports Event Log
function Get-CriticalEventXML
{ 
    [cmdletbinding()]
    Param
    (
        [Parameter()]
        [PSCustomObject]
        $EventList,

        [DateTime]
        $BeginTime,

        [DateTime]
        $EndTime,

        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }

    Process
    {
        $local_path = ($env:USERPROFILE + '\AppData\Local\Temp\XML\') # directory where XML files will be stored on your machine
        $export_path = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {"$env:USERPROFILE\AppData\Local\Temp\" + $env:COMPUTERNAME + "-events.xml"} # Directory where xml file will be saved on endpoint

        if (-not (Test-Path -Path $local_path -PathType Container)) {New-Item -Path ($env:USERPROFILE + '\AppData\Local\Temp') -Name XML -ItemType Directory } # create the dir if it doesn't exist


        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            
            $events = foreach ($event in $using:EventList) {
                 Get-WinEvent -FilterHashtable @{ LogName = $event.Event_Log; StartTime=$using:BeginTime; EndTime=$using:EndTime; Id=$event.ID} -ErrorAction Ignore
                    }
            
            $events | Export-Clixml -Path $using:export_path

        }

        # PSSession to pull the file back
        $session = New-PSSession -ComputerName $ComputerName -Credential $Credential

        # Copy the file from the remote machine to your local machine
        Copy-Item -Path $export_path -Destination $local_path -FromSession $session

        # Remove event log from remote machine
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock { Remove-Item -Path $using:export_path }
    }
}


<# Example
$BeginTime = (Get-Date).AddDays(-7)
$EndTime = Get-Date


$ComputerNames = 'COMPUTER1', 'COMPUTER2', 'COMPUTER3'  # Replace with actual computer names
$Credential = Get-Credential

$local_path = ($env:USERPROFILE + '\AppData\Local\Temp\XML\')

Get-CriticalEventXML -EventList $EventList -BeginTime $BeginTime -EndTime $EndTime -ComputerName $ComputerNames -Credential $Credential

# Merge XML files into a single file
$allEvents = Get-ChildItem -Path $localPath -Filter "*-events.xml" | ForEach-Object {
    Import-Clixml -Path $_.FullName
}

$allEvents | Export-Clixml -Path $OutputPath

#>


# Enrich Events -- This is meant to have event objects passed to it
function Enrich-Event {
    [cmdletbinding()]
    Param (
        [Parameter(ValueFromPipeline=$true,Mandatory=$true)]
        [Array]
        $Events
    )

    Process {
        foreach ($event in $Events) {
            if ($event.Id -eq '4624') {
                [regex]$regex = '\s[\d]{1,2}\s'
                $LogonType = $regex.Matches($event[0].Message)[0].Value
                [PSCustomObject]@{
                    Id = $event.Id
                    LogName = $event.LogName
                    Description = "User Logon"
                    TimeCreated = $event.TimeCreated
                    MachineName = $event.MachineName
                    RecordId = $event.RecordId
                    SecurityID = $event.Properties[0].Value
                    AccountName = $event.Properties[1].Value
                    AccountDomain = $event.Properties[2].Value
                    LogonID = $event.Properties[3].Value
                    ProcessId = $event.Properties[16].Value
                    ProcessName = $event.Properties[17].Value
                    WorkstationName = $event.Properties[18].Value
                    SourceNetworkAddress = $event.Properties[19].Value
                    SourcePort = $event.Properties[20].Value
                    LogonProcess = $event.Properties[21].Value
                    LogonType = $LogonType
                }
            } elseif ($event.Id -eq '4625') {
                [regex]$regex = '\s[\d]{1,2}\s'
                $LogonType = $regex.Matches($event[0].Message)[0].Value
                [PSCustomObject]@{
                    Id = $event.Id
                    LogName = $event.LogName
                    Description = "Failed Logon"
                    TimeCreated = $event.TimeCreated
                    MachineName = $event.MachineName
                    RecordId = $event.RecordId
                    SecurityID = $event.Properties[0].Value
                    AccountName = $event.Properties[1].Value
                    AccountDomain = $event.Properties[2].Value
                    LogonID = $event.Properties[3].Value
                    ProcessID = $event.Properties[17].Value
                    ProcessName = $event.Properties[18].Value
                    WorkstationName = $event.Properties[19].Value
                    SourceNetworkAddress = $event.Properties[20].Value
                    SourcePort = $event.Properties[21].Value
                    LogonType = $LogonType
                }
            } elseif ($event.id -eq '4648') {
                [PSCustomObject]@{
                    Id = $event.Id
                    LogName = $event.LogName
                    Description = "Process Launch"
                    TimeCreated = $event.TimeCreated
                    MachineName = $event.MachineName
                    RecordId = $event.RecordId
                    SecurityId = $event.Properties[0].value
                    AccountName = $event.Properties[1].value
                    AccountDomain = $event.Properties[2].value
                    LogonId = $event.Properties[3].value
                    AccountCredentialsUsed = $event.Properties[5].value
                    AccountCredentials = $event.Properties[6].value
                    TargetServerName = $event.Properties[8].value
                    ProcessId = $event.Properties[10].value
                    ProcessName = $event.Properties[11].value
                    SourceNetworkAddress = $event.Properties[12].value
                    SourcePort = $event.Properties[13].value
                }
            } elseif ($event.id -eq '4672') {
                [PSCustomObject]@{
                    Id = $event.Id
                    LogName = $event.LogName
                    Description = "Process Launch"
                    TimeCreated = $event.TimeCreated
                    MachineName = $event.MachineName
                    RecordId = $event.RecordId
                    SecurityId = $event.Properties[0].value
                    AccountName = $event.Properties[1].value
                    AccountDomain = $event.Properties[2].value
                    LogonId = $event.Properties[3].value
                    Privileges = $event.Properties[4].value
                }
            } elseif ($event.id -eq '4673') {
                [PSCustomObject]@{
                    Id = $event.Id
                    LogName = $event.LogName
                    Description = "Process Launch"
                    TimeCreated = $event.TimeCreated
                    MachineName = $event.MachineName
                    RecordId = $event.RecordId
                    SecurityId = $event.Properties[0].value
                    AccountName = $event.Properties[1].value
                    AccountDomain = $event.Properties[2].value
                    LogonId = $event.Properties[3].value
                    Server = $event.Properties[4].value
                    ServiceName = $event.Properties[5].value
                    ProcessId = $event.Properties[6].value
                    ProcessName = $event.Properties[7].value
                    Privileges = $event.Properties[8].value
                }
            } elseif ($event.Id -eq '4688') {
                [PSCustomObject]@{
                    Id = $event.Id
                    LogName = $event.LogName
                    Description = "Process Launch"
                    TimeCreated = $event.TimeCreated
                    MachineName = $event.MachineName
                    RecordId = $event.RecordId
                    SecurityID = $event.Properties[0].Value
                    AccountName = $event.Properties[1].Value
                    AccountDomain = $event.Properties[2].Value
                    LogonID = $event.Properties[3].Value
                    ProcessID = $event.Properties[4].Value
                    ProcessName = $event.Properties[5].Value
                    CommandLine = $event.Properties[8].Value
                    ParentProcessID = $event.Properties[7].Value
                    ParentProcessName = $event.Properties[13].Value
                }
            } elseif ($event.Id -eq '4698') {
                [PSCustomObject]@{
                    Id = $event.Id
                    LogName = $event.LogName
                    Description = "Schedule Task Creation"
                    TimeCreated = $event.TimeCreated
                    MachineName = $event.MachineName
                    RecordId = $event.RecordId
                    SecurityID = $event.Properties[0].Value
                    AccountName = $event.Properties[1].Value
                    AccountDomain = $event.Properties[2].Value
                    TaskName = $event.Properties[4].Value
                    TaskContent = $event.Properties[5].Value
                    ProcessID = $event.Properties[7].Value
                    ParentProcessID = $event.Properties[8].Value
                }
            } elseif ($event.Id -eq '4702') {
                [PSCustomObject]@{
                    Id = $event.Id
                    LogName = $event.LogName
                    Description = "Schedule Task Updated"
                    TimeCreated = $event.TimeCreated
                    MachineName = $event.MachineName
                    RecordId = $event.RecordId
                    SecurityID = $event.Properties[0].Value
                    AccountName = $event.Properties[1].Value
                    AccountDomain = $event.Properties[2].Value
                    TaskName = $event.Properties[4].Value
                    TaskContent = $event.Properties[4].Value
                    ProcessID = $event.Properties[7].Value
                    ParentProcessID = $event.Properties[8].Value
                }
            } elseif ($event.Id -eq '4740') {
                [PSCustomObject]@{
                    Id = $event.Id
                    LogName = $event.LogName
                    Description = "User Account Lockout"
                    TimeCreated = $event.TimeCreated
                    MachineName = $event.MachineName
                    RecordId = $event.RecordId
                    SecurityID = $event.Properties[2].Value
                    AccountName = $event.Properties[0].Value
                    ComputerName = $event.Properties[1].Value
                }
            } elseif ($event.Id -eq '4769') {
                [PSCustomObject]@{
                    Id = $event.Id
                    LogName = $event.LogName
                    Description = "User Account Lockout"
                    TimeCreated = $event.TimeCreated
                    MachineName = $event.MachineName
                    RecordId = $event.RecordId
                    AccountName = $event.Properties[0].Value
                    AccountDomain = $event.Properties[1].Value
                    ServiceName = $event.Properties[2].Value
                    ServiceId = $event.Properties[3].Value
                    ClientAddress = $event.Properties[4].Value
                    ClientPort = $event.Properties[5].Value
                    TicketOptions = $event.Properties[6].Value
                    TicketEncryptionType = $event.Properties[7].Value
                    FailureCode = $event.Properties[8].Value
                }
            } elseif ($event.Id -eq '4771') {
                [PSCustomObject]@{
                    Id = $event.Id
                    LogName = $event.LogName
                    Description = "User Account Lockout"
                    TimeCreated = $event.TimeCreated
                    MachineName = $event.MachineName
                    RecordId = $event.RecordId
                    SecurityId = $event.Properties[1].Value
                    AccountName = $event.Properties[0].Value
                    ServiceName = $event.Properties[2].Value
                    ClientAddress = $event.Properties[6].Value
                    FailureCode = $event.Properties[4].Value
                    PreAuthenticationType = $event.Properties[5].Value
                }
            } elseif ($event.Id -eq '5152') {
                [PSCustomObject]@{
                    Id = $event.Id
                    LogName = $event.LogName
                    Description = "Windows Filtering Blocked a Packet"
                    TimeCreated = $event.TimeCreated
                    MachineName = $event.MachineName
                    RecordId = $event.RecordId
                    ProcessID = $event.Properties[0].Value
                    ApplicationName = $event.Properties[1].Value
                    SourceAddress = $event.Properties[3].Value
                    SourcePort = $event.Properties[4].Value
                    DestinationAddress = $event.Properties[5].Value
                    DestinationPort = $event.Properties[6].Value
                    Protocol = $event.Properties[7].Value
                }
            } elseif ($event.Id -eq '5154') {
                [PSCustomObject]@{
                    Id = $event.Id
                    LogName = $event.LogName
                    Description = "Listening Port Opened"
                    TimeCreated = $event.TimeCreated
                    MachineName = $event.MachineName
                    RecordId = $event.RecordId
                }
            } elseif ($event.Id -eq '5155') {
                [PSCustomObject]@{
                    Id = $event.Id
                    LogName = $event.LogName
                    Description = "Windows Filtering Platform Connection"
                    TimeCreated = $event.TimeCreated
                    MachineName = $event.MachineName
                    RecordId = $event.RecordId
                    ProcessID = $event.Properties[0].Value
                    ApplicationName = $event.Properties[1].Value
                    SourceAddress = $event.Properties[3].Value
                    SourcePort = $event.Properties[4].Value
                    DestinationAddress = $event.Properties[5].Value
                    DestinationPort = $event.Properties[6].Value
                    Protocol = $event.Properties[7].Value
                    FilterInformation = $event.Properties[8].Value
                    LayerName = $event.Properties[9].Value
                }
            } else {
                Write-Warning "Unknown event ID: $($event.Id)"
            }
        }
    }
}

<# Example

$BeginTime = (Get-Date).AddDays(-7)
$EndTime = Get-Date


$ComputerNames = 'COMPUTER1', 'COMPUTER2', 'COMPUTER3'  # Replace with actual computer names
$Credential = Get-Credential

$local_path = ($env:USERPROFILE + '\AppData\Local\Temp\XML\')

Get-CriticalEventXML -EventList $EventList -BeginTime $BeginTime -EndTime $EndTime -ComputerName $ComputerNames -Credential $Credential

# Merge XML files into a single file
$allEvents = Get-ChildItem -Path $localPath -Filter "*-events.xml" | ForEach-Object {
    Import-Clixml -Path $_.FullName
}

$allEvents | Enrich-Event

#>

# Function that exports event logs to an EVTX file and copies it back to your machine
function Get-EVTX
{

 [cmdletbinding()]
 Param
 (
    [Parameter(ValueFromPipeline=$true,Mandatory=$true)]
    [string[]]
    $ComputerName,

    [Parameter(Mandatory=$true)]
    [pscredential]
    $Credential,

    [Parameter(Mandatory=$false)]
    [string]
    $LogName='Security',

    [Parameter(Mandatory=$false)]
    [string]
    $StartDate = (Get-Date).AddDays(-2),

    [Parameter(Mandatory=$false)]
    [string]
    $EndDate = (Get-Date),

    [Parameter(Mandatory=$false)]
    [string]
    $LocalPath = "$env:USERPROFILE\Desktop\" + $LogName + ".evtx"

)

Begin
{
    If (!$Credential) {$Credential = Get-Credential}
}

Process
{ 
    $export_path = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {"$env:USERPROFILE\AppData\Local\Temp\$using:LogName" + "_Exported.evtx"}

    Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {

    # create time frame
    function GetMilliseconds ($date) {
        $ts = New-TimeSpan -Start $date -End (Get-Date)
        $ts.Ticks / 10000 # Divide by 10,000 to convert ticks to milliseconds
        } 

     $StartMilliseconds = GetMilliseconds $using:StartDate
     $EndMilliseconds = GetMilliseconds $using:EndDate

    # Event Log Query
    $query = "*[System[TimeCreated[timediff(@SystemTime) >= $EndMilliseconds and timediff(@SystemTime) <= $StartMilliseconds]]]"

    # Create the EventLogSession Object
    $EventSession = New-Object System.Diagnostics.Eventing.Reader.EventLogSession

     # Test if destination file already exists
    if(Test-Path -Path $using:export_path)
    {
       return Write-Error -Message "File already exists"
    }


    # Export the log and messages
    $EventSession.ExportLogAndMessages($using:LogName, [System.Diagnostics.Eventing.Reader.PathType]::LogName,$query, $using:export_path)


}#End of Script Block


# Create a session with the remote machine
$session = New-PSSession -ComputerName $ComputerName -Credential $creds

# Copy the file from the remote machine to your local machine
Copy-Item -Path $export_path -Destination $LocalPath -FromSession $session

# Remove event log from remote machine
Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock { Remove-Item -Path $using:export_path }

}#End of Process
}

<# Example
Get-EVTX -ComputerName $ComputerName -Credential $Credential -LogName 'Security'
#>

