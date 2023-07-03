# PROCESSES
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
        $processes = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            Get-WmiObject win32_Process | ForEach-Object {
                [PSCustomObject]@{
                    "CSName" = $_.CSName
                    "Name" = $_.Name
                    "ProcessID" = $_.ProcessID
                    "ParentProcessName" = (Get-Process -id $_.ParentProcessId).Name
                    "ParentProcessID" = $_.ParentProcessID
                    "HandleCount" = $_.HandleCount
                    "ThreadCount" = $_.ThreadCount
                    "Path" = $_.Path
                    "CommandLine" = $_.CommandLine
                    "PSComputerName" = $_.PSComputerName
                    "RunspaceId" = $_.RunspaceId
                    "PSShowComputerName" = $true
                    "Time" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
                }
            }
        }
        $processes
    }
} 

# Change creds as needed
$username = 'Administrator'
$password = 'P@55w0rd!'

# Create Credential Object
[SecureString]$secureString = $password | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureString

$Processes = (Get-WmiProcess -ComputerName "10.136.36.54" -Credential $creds)


# Elasticsearch server URL
$elasticsearchUrl = "https://10.109.35.100:9200"

# Index name
$indexName = "hap-processes"

# Create the Elasticsearch document endpoint URL
$documentUrl = "$elasticsearchUrl/$indexName/_doc"

# Elasticsearch credentials
$elasticUsername = 'elastic'
$elasticPassword = 'Fy590f0TI7Wg7L0MO4Og44gd' # Password is on the TFPlenum home page

# Create Elasticsearch Credential Object
[SecureString]$elasticSecureString = ConvertTo-SecureString -String $elasticPassword -AsPlainText -Force
[PSCredential]$elasticCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $elasticUsername, $elasticSecureString


<# This code will loop through each PowerShell object in the array 
and send a document to the Elastic API #>

foreach ($process in $Processes)
{
    $process = @{
    "processes" = $process
    }

    # Convert the $Processes to JSON
    $jsonData = $process | ConvertTo-Json

    # Ignore SSL certificate validation
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

    # Send the JSON data as the request body to create the document
    Invoke-RestMethod -Method 'POST' -Uri $documentUrl -Body $jsonData -ContentType 'application/json' -Credential $elasticCredentials

}




# SERVICES
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
        $services = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            Get-CimInstance -Class Win32_Service | ForEach-Object {
                [PSCustomObject]@{
                    "Name" = $_.Name
                    "State" = $_.State
                    "SystemName" = $_.SystemName
                    "DisplayName" = $_.DisplayName
                    "Description" = $_.Description
                    "PathName" = $_.PathName
                    "InstallDate" = $_.InstallDate
                    "ProcessId" = $_.ProcessId
                    "ProcessName" = (Get-WmiObject -Class Win32_Process -Filter "ProcessId='$($_.ProcessId)'").Name
                    "ParentProcessID" = (Get-WmiObject -Class Win32_Process -Filter "ProcessId='$($_.ProcessId)'").ParentProcessID
                    "ParentProcessName" = (Get-Process -ID (Get-WmiObject -Class Win32_Process -Filter "ProcessId='$($_.ProcessId)'").ParentProcessID).Name
                    "StartMode" = $_.StartMode
                    "ExitCode" = $_.ExitCode
                    "DelayedAutoStart" = $_.DelayedAutoStart
                    "Time" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
                }
            }
        }
        $services
    }
} 

# Change creds as needed
$username = 'Administrator'
$password = 'P@55w0rd!'

# Create Credential Object
[SecureString]$secureString = $password | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureString

$Services = (Get-ServiceInfo -ComputerName "10.136.36.54" -Credential $creds)

# Elasticsearch server URL
$elasticsearchUrl = "https://10.109.35.100:9200"

# Index name
$indexName = "hap-services"

# Create the Elasticsearch document endpoint URL
$documentUrl = "$elasticsearchUrl/$indexName/_doc"

# Elasticsearch credentials
$elasticUsername = 'elastic'
$elasticPassword = 'Fy590f0TI7Wg7L0MO4Og44gd' # Password is on the TFPlenum home page

# Create Elasticsearch Credential Object
[SecureString]$elasticSecureString = ConvertTo-SecureString -String $elasticPassword -AsPlainText -Force
[PSCredential]$elasticCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $elasticUsername, $elasticSecureString

# Loop through each PowerShell object in the array and send a document to the Elastic API
foreach ($service in $Services)
{
    $serviceData = @{
        "services" = $service
    }

    # Convert the $serviceData to JSON
    $jsonData = $serviceData | ConvertTo-Json

    # Ignore SSL certificate validation
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

    # Send the JSON data as the request body to create the document
    Invoke-RestMethod -Method 'POST' -Uri $documentUrl -Body $jsonData -ContentType 'application/json' -Credential $elasticCredentials
}


# CONNECTIONS
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
        $connections = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
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
                    Time             = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
                }
            }
        }
        $connections
    }
}

# Change creds as needed
$username = 'Administrator'
$password = 'P@55w0rd!'

# Create Credential Object
[SecureString]$secureString = $password | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureString

$Connections = (Get-Connection -ComputerName "10.136.36.54" -Credential $creds)

# Elasticsearch server URL
$elasticsearchUrl = "https://10.109.35.100:9200"

# Index name
$indexName = "hap-connections"

# Create the Elasticsearch document endpoint URL
$documentUrl = "$elasticsearchUrl/$indexName/_doc"

# Elasticsearch credentials
$elasticUsername = 'elastic'
$elasticPassword = 'Fy590f0TI7Wg7L0MO4Og44gd' # Password is on the TFPlenum home page

# Create Elasticsearch Credential Object
[SecureString]$elasticSecureString = ConvertTo-SecureString -String $elasticPassword -AsPlainText -Force
[PSCredential]$elasticCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $elasticUsername, $elasticSecureString

# This code will loop through each PowerShell object in the array
# and send a document to the Elastic API

foreach ($connection in $Connections) {
    $connectionData = @{
        "connections" = $connection
    }

    # Convert the $Connections to JSON
    $jsonData = $connectionData | ConvertTo-Json

    # Ignore SSL certificate validation
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

    # Send the JSON data as the request body to create the document
    Invoke-RestMethod -Method 'POST' -Uri $documentUrl -Body $jsonData -ContentType 'application/json' -Credential $elasticCredentials
}


# SCHEDULED TASKS
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
        $tasks = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock { 
            $schtasks = (Get-ScheduledTask)
            $taskInfoList = @()

            foreach ($task in $schtasks)
            {
                $taskinfo = Get-ScheduledTaskInfo -TaskPath $task.TaskPath -TaskName $task.TaskName
                $taskInfoList += [PSCustomObject]@{
                    TaskName        = $task.TaskName
                    Author          = $task.Author
                    Date            = $task.Date
                    URI             = $task.URI
                    State           = $task.State
                    TaskPath        = $task.TaskPath
                    LastRunTime     = $taskinfo.LastRunTime
                    LastTaskResult  = $taskinfo.LastTaskResult
                    NextRunTime     = $taskinfo.NextRunTime
                    Time            = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
                }
            }
            $taskInfoList
        }

        $tasks
    }    
}

# Change creds as needed
$username = 'Administrator'
$password = 'P@55w0rd!'

# Create Credential Object
[SecureString]$secureString = $password | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureString

$Tasks = (Get-SchTask -ComputerName "10.136.36.54" -Credential $creds)

# Elasticsearch server URL
$elasticsearchUrl = "https://10.109.35.100:9200"

# Index name
$indexName = "hap-tasks"

# Create the Elasticsearch document endpoint URL
$documentUrl = "$elasticsearchUrl/$indexName/_doc"

# Elasticsearch credentials
$elasticUsername = 'elastic'
$elasticPassword = 'Fy590f0TI7Wg7L0MO4Og44gd' # Password is on the TFPlenum home page

# Create Elasticsearch Credential Object
[SecureString]$elasticSecureString = ConvertTo-SecureString -String $elasticPassword -AsPlainText -Force
[PSCredential]$elasticCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $elasticUsername, $elasticSecureString

# This code will loop through each PowerShell object in the array
# and send a document to the Elastic API

foreach ($task in $Tasks) {
    $taskData = @{
        "tasks" = $task
    }

    # Convert the $Tasks to JSON
    $jsonData = $taskData | ConvertTo-Json

    # Ignore SSL certificate validation
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

    # Send the JSON data as the request body to create the document
    Invoke-RestMethod -Method 'POST' -Uri $documentUrl -Body $jsonData -ContentType 'application/json' -Credential $elasticCredentials
}



# PREFETCH
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
        $prefetchData = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $pfconf = (Get-ItemProperty "hklm:\system\currentcontrolset\control\session manager\memory management\prefetchparameters").EnablePrefetcher 

            Switch -Regex ($pfconf) {
                "[1-3]" {
                    $prefetches = ls $env:windir\Prefetch\*.pf | ForEach-Object {
                        [PSCustomObject]@{
                            FullName           = $_.FullName
                            CreationTimeUtc    = $_.CreationTimeUtc.ToString("o")
                            LastAccessTimeUtc  = $_.LastAccessTimeUtc.ToString("o")
                            LastWriteTimeUtc   = $_.LastWriteTimeUtc.ToString("o")
                            Time               = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
                        }
                    }
                    $prefetches
                }
                default {
                    Write-Output "Prefetch not enabled on ${env:COMPUTERNAME}."
                }
            }
        }

        $prefetchData
    }
}

# Change creds as needed
$username = 'Administrator'
$password = 'P@55w0rd!'

# Create Credential Object
[SecureString]$secureString = $password | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureString

$Prefetches = (Get-Prefetch -ComputerName "10.136.36.54" -Credential $creds)

# Elasticsearch server URL
$elasticsearchUrl = "https://10.109.35.100:9200"

# Index name
$indexName = "hap-prefetches"

# Create the Elasticsearch document endpoint URL
$documentUrl = "$elasticsearchUrl/$indexName/_doc"

# Elasticsearch credentials
$elasticUsername = 'elastic'
$elasticPassword = 'Fy590f0TI7Wg7L0MO4Og44gd' # Password is on the TFPlenum home page

# Create Elasticsearch Credential Object
[SecureString]$elasticSecureString = ConvertTo-SecureString -String $elasticPassword -AsPlainText -Force
[PSCredential]$elasticCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $elasticUsername, $elasticSecureString

# This code will loop through each PowerShell object in the array
# and send a document to the Elastic API

foreach ($prefetch in $Prefetches) {
    $prefetchData = @{
        "prefetches" = $prefetch
    }

    # Convert the $Prefetches to JSON
    $jsonData = $prefetchData | ConvertTo-Json

    # Ignore SSL certificate validation
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

    # Send the JSON data as the request body to create the document
    Invoke-RestMethod -Method 'POST' -Uri $documentUrl -Body $jsonData -ContentType 'application/json' -Credential $elasticCredentials
}


# OS INFORMATION
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
        $osInfo = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {Get-CimInstance -ClassName Win32_OperatingSystem}

        $osData = $osInfo | ForEach-Object {
            [PSCustomObject]@{
                "ComputerName"           = $_.CSName
                "OperatingSystem"        = $_.Caption
                "OperatingSystemVersion" = $_.Version
                "Manufacturer"           = $_.Manufacturer
                "RegisteredOwner"        = $_.RegisteredUser
                "InstallDate"            = $_.InstallDate
                "LastBootTime"           = $_.LastBootUpTime
                "SerialNumber"           = $_.SerialNumber
                "Time"                   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
            }
        }

        $osData
    }
}

# Change creds as needed
$username = 'Administrator'
$password = 'P@55w0rd!'

# Create Credential Object
[SecureString]$secureString = $password | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureString

$OSInfo = (Get-OSInfo -ComputerName "10.136.36.54" -Credential $creds)

# Elasticsearch server URL
$elasticsearchUrl = "https://10.109.35.100:9200"

# Index name
$indexName = "hap-osinfo"

# Create the Elasticsearch document endpoint URL
$documentUrl = "$elasticsearchUrl/$indexName/_doc"

# Elasticsearch credentials
$elasticUsername = 'elastic'
$elasticPassword = 'Fy590f0TI7Wg7L0MO4Og44gd' # Password is on the TFPlenum home page

# Create Elasticsearch Credential Object
[SecureString]$elasticSecureString = ConvertTo-SecureString -String $elasticPassword -AsPlainText -Force
[PSCredential]$elasticCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $elasticUsername, $elasticSecureString

# This code will loop through each PowerShell object in the array
# and send a document to the Elastic API

foreach ($os in $OSInfo) {
    $osData = @{
        "osInfo" = $os
    }

    # Convert the $OSInfo to JSON
    $jsonData = $osData | ConvertTo-Json

    # Ignore SSL certificate validation
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

    # Send the JSON data as the request body to create the document
    Invoke-RestMethod -Method 'POST' -Uri $documentUrl -Body $jsonData -ContentType 'application/json' -Credential $elasticCredentials
}


# REGISTRY
function Get-RegistryRun
{
    [CmdletBinding()]
    Param
    (
        [Parameter(ValueFromPipeline = $true)]
        [String[]]
        $ComputerName,

        [PSCredential]
        $Credential
    )

    Begin
    {
        If (!$Credential) {
            $Credential = Get-Credential
        }
    }

    Process
    {
        $registryRunKeys = @(
            [PSCustomObject]@{
                Key         = "HKCU:\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"
                Description = "This key contains the list of programs that are configured to run when the current user logs in"
            },
            [PSCustomObject]@{
                Key         = "HKCU:\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce"
                Description = "This key contains the list of programs that are configured to run once when the current user logs in"
            },
            [PSCustomObject]@{
                Key         = "HKLM:\HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
                Description = "This key contains the list of programs that are configured to run when any user logs in"
            },
            [PSCustomObject]@{
                Key         = "HKLM:\HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce"
                Description = "This key contains the list of programs that are configured to run once when any user logs in"
            },
            [PSCustomObject]@{
                Key         = "HKCU:\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
                Description = "This key stores the paths to special folders for the current user, such as the Desktop, Start Menu, and Favorites"
            },
            [PSCustomObject]@{
                Key         = "HKCU:\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
                Description = "This key stores the paths to common shell folders for the current user"
            },
            [PSCustomObject]@{
                Key         = "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
                Description = "This key stores the paths to common shell folders for all users on the machine"
            },
            [PSCustomObject]@{
                Key         = "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
                Description = "This key stores the paths to special folders for all users on the machine"
            },
            [PSCustomObject]@{
                Key         = "HKLM:\HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
                Description = "This key contains the list of services that are configured to run once when the system starts"
            },
            [PSCustomObject]@{
                Key         = "HKCU:\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
                Description = "This key contains the list of services that are configured to run once when the user logs in"
            },
            [PSCustomObject]@{
                Key         = "HKLM:\HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices"
                Description = "This key contains the list of services that are configured to run when the system starts"
            },
            [PSCustomObject]@{
                Key         = "HKCU:\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices"
                Description = "This key contains the list of services that are configured to run when the user logs in"
            }
        )

        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $registryRunData = foreach ($runKey in $using:registryRunKeys) {
                $key = $runKey.Key
                $description = $runKey.Description
                if (Test-Path $key) {
                    Get-ItemProperty -Path $key | Select-Object -Property *, @{Name = 'Description'; Expression = {$using:description}}
                }
            }

            $registryRunData
        }
    }
}

# Change creds as needed
$username = 'Administrator'
$password = 'P@55w0rd!'

# Create Credential Object
[SecureString]$secureString = $password | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureString

$RegistryRun = Get-RegistryRun -ComputerName "10.136.36.54" -Credential $creds

# Elasticsearch server URL
$elasticsearchUrl = "https://10.109.35.100:9200"

# Index name
$indexName = "hap-registryrun"

# Create the Elasticsearch document endpoint URL
$documentUrl = "$elasticsearchUrl/$indexName/_doc"

# Elasticsearch credentials
$elasticUsername = 'elastic'
$elasticPassword = 'Fy590f0TI7Wg7L0MO4Og44gd' # Password is on the TFPlenum home page

# Create Elasticsearch Credential Object
[SecureString]$elasticSecureString = ConvertTo-SecureString -String $elasticPassword -AsPlainText -Force
[PSCredential]$elasticCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $elasticUsername, $elasticSecureString

# This code will loop through each PowerShell object in the array
# and send a document to the Elastic API

foreach ($item in $RegistryRun) {
    $registryData = @{
        "registryRun" = $item
    }

    # Convert the $RegistryRun to JSON
    $jsonData = $registryData | ConvertTo-Json

    # Ignore SSL certificate validation
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

    # Send the JSON data as the request body to create the document
    Invoke-RestMethod -Method 'POST' -Uri $documentUrl -Body $jsonData -ContentType 'application/json' -Credential $elasticCredentials
}

# STARTUPS
function Get-StartupFolders
{
    [CmdletBinding()]
    Param
    (
        [String[]]
        $ComputerName,

        [PSCredential]
        $Credential
    )

    Begin
    {
        If (!$Credential) {
            $Credential = Get-Credential
        }
    }

    Process
    {
        $startupFolders = @(
            @{
                Path        = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
                Description = "User Startup Folder"
            }
            @{
                Path        = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
                Description = "All Users Startup Folder"
            }
        )

        $startupData = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            foreach ($folder in $using:startupFolders)
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
                                Path         = $folder.Path
                                Description  = $folder.Description
                                Name         = $fileInfo.Name
                                Size         = $fileInfo.Length
                                LastWriteTime = $fileInfo.LastWriteTime
                            }
                        }
                    }
                }
            }
        }

        return $startupData
    }
}

# Change creds as needed
$username = 'Administrator'
$password = 'P@55w0rd!'

# Create Credential Object
[SecureString]$secureString = $password | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureString

# Specify the target computer name
$computerName = "10.136.36.54"

# Retrieve startup folders data using Get-StartupFolders function
$startupData = Get-StartupFolders -ComputerName $computerName -Credential $creds

# Elasticsearch server URL
$elasticsearchUrl = "https://10.109.35.100:9200"

# Index name
$indexName = "hap-startupfolders"

# Elasticsearch credentials
$elasticUsername = 'elastic'
$elasticPassword = 'Fy590f0TI7Wg7L0MO4Og44gd' # Password is on the TFPlenum home page

# Create Elasticsearch Credential Object
[SecureString]$elasticSecureString = ConvertTo-SecureString -String $elasticPassword -AsPlainText -Force
[PSCredential]$elasticCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $elasticUsername, $elasticSecureString

# Set SSL certificate validation callback
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Create the Elasticsearch document endpoint URL
$documentUrl = "$elasticsearchUrl/$indexName/_doc"

# Loop through each startup item, convert to JSON, and send to Elasticsearch
foreach ($startupItem in $startupData) {
    $startupDataObj = @{
        "startupItem" = $startupItem
    }

    $jsonData = $startupDataObj | ConvertTo-Json

    # Send the JSON data as the request body to create the document
    Invoke-RestMethod -Method 'POST' -Uri $documentUrl -Body $jsonData -ContentType 'application/json' -Credential
}


# LOCAL USERS
function Get-LUser
{
    [CmdletBinding()]
    Param
    (
        [Parameter(ValueFromPipeline = $true)]
        [String[]]
        $ComputerName,

        [PSCredential]
        $Credential
    )

    Begin
    {
        If (!$Credential) {
            $Credential = Get-Credential
        }
    }

    Process
    {
        $usersData = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | ForEach-Object {
                [PSCustomObject]@{
                    "Name" = $_.Name
                    "SID" = $_.SID
                    "Status" = $_.Status
                    "AccountType" = $_.AccountType
                    "Caption" = $_.Caption
                    "Description" = $_.Description
                    "Domain" = $_.Domain
                    "Disabled" = $_.Disabled
                    "LocalAccount" = $_.LocalAccount
                    "Lockout" = $_.Lockout
                    "PasswordChangeable" = $_.PasswordChangeable
                    "PasswordExpires" = $_.PasswordExpires
                    "PasswordRequired" = $_.PasswordRequired
                    "SIDType" = $_.SIDType
                    "FullName" = $_.FullName
                    "AccountExpires" = $_.AccountExpires
                    "Time" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
                }
            }
        }

        return $usersData
    }
}

# Change creds as needed
$username = 'Administrator'
$password = 'P@55w0rd!'

# Create Credential Object
[SecureString]$secureString = $password | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureString

# Specify the target computer name
$computerName = "10.136.36.54"

# Retrieve local users using Get-LUser function
$users = Get-LUser -ComputerName $computerName -Credential $creds

# Elasticsearch server URL
$elasticsearchUrl = "https://10.109.35.100:9200"

# Index name
$indexName = "hap-localusers"

# Elasticsearch credentials
$elasticUsername = 'elastic'
$elasticPassword = 'Fy590f0TI7Wg7L0MO4Og44gd' # Password is on the TFPlenum home page

# Create Elasticsearch Credential Object
[SecureString]$elasticSecureString = ConvertTo-SecureString -String $elasticPassword -AsPlainText -Force
[PSCredential]$elasticCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $elasticUsername, $elasticSecureString

# Set SSL certificate validation callback
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Create the Elasticsearch document endpoint URL
$documentUrl = "$elasticsearchUrl/$indexName/_doc"

# Loop through each user, convert to JSON, and send to Elasticsearch
foreach ($user in $users) {
    $userData = @{
        "user" = $user
    }

    $jsonData = $userData | ConvertTo-Json

    # Send the JSON data as the request body to create the document
    Invoke-RestMethod -Method 'POST' -Uri $documentUrl -Body $jsonData -ContentType 'application/json' -Credential $elasticCredentials
}



# LOCAL GROUPS
function Get-LGroup
{
    [CmdletBinding()]
    Param
    (
        [Parameter(ValueFromPipeline = $true)]
        [String[]]
        $ComputerName,

        [PSCredential]
        $Credential
    )

    Begin
    {
        If (!$Credential) {
            $Credential = Get-Credential
        }
    }

    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            Get-WmiObject -Class Win32_Group
        } | ForEach-Object {
            [PSCustomObject]@{
                "Name" = $_.Name
                "SID" = $_.SID
                "Domain" = $_.Domain
                "Caption" = $_.Caption
                "Description" = $_.Description
                "LocalAccount" = $_.LocalAccount
                "SIDType" = $_.SIDType
                "Time" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
            }
        }
    }
}

# Change creds as needed
$username = 'Administrator'
$password = 'P@55w0rd!'

# Create Credential Object
[SecureString]$secureString = $password | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureString

$groups = Get-LGroup -ComputerName "10.136.36.54" -Credential $creds

# Elasticsearch server URL
$elasticsearchUrl = "https://10.109.35.100:9200"

# Index name
$indexName = "hap-localgroups"

# Elasticsearch credentials
$elasticUsername = 'elastic'
$elasticPassword = 'Fy590f0TI7Wg7L0MO4Og44gd' # Password is on the TFPlenum home page

# Create Elasticsearch Credential Object
[SecureString]$elasticSecureString = ConvertTo-SecureString -String $elasticPassword -AsPlainText -Force
[PSCredential]$elasticCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $elasticUsername, $elasticSecureString

# Set SSL certificate validation callback
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Create the Elasticsearch document endpoint URL
$documentUrl = "$elasticsearchUrl/$indexName/_doc"

# Loop through each group, convert to JSON, and send to Elasticsearch
foreach ($group in $groups) {
    $groupData = @{
        "group" = $group
    }

    $jsonData = $groupData | ConvertTo-Json

    # Send the JSON data as the request body to create the document
    Invoke-RestMethod -Method 'POST' -Uri $documentUrl -Body $jsonData -ContentType 'application/json' -Credential $elasticCredentials
}


# LOCAL GROUP MEMBERS
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
        If (!$Credential) {
            $Credential = Get-Credential
        }
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            try
            {
                foreach ($name in (Get-WmiObject -Class Win32_Group).Name) {
                    [PSCustomObject]@{
                        GroupName = $name 
                        Member    = (Get-LocalGroupMember $name)                                   
                    }
                }
            }
            catch
            {
                foreach ($name in (Get-WmiObject -Class Win32_Group).Name) {
                    [PSCustomObject]@{
                        GroupName = $name 
                        Member    = Get-WmiObject win32_groupuser | Where-Object {$_.groupcomponent -like "*$name*"} | ForEach-Object {  
                            $_.partcomponent –match ".+Domain\=(.+)\,Name\=(.+)$" > $null  
                            $matches[1].trim('"') + "\" + $matches[2].trim('"')  
                        }  
                    }
                }
            }
        }
    } 
}

# Change creds as needed
$username = 'Administrator'
$password = 'P@55w0rd!'

# Create Credential Object
[SecureString]$secureString = $password | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureString

# Specify the target computer name
$computerName = "10.136.36.54"

# Retrieve group members data using Get-LGroupMembers function
$groupMembersData = Get-LGroupMembers -ComputerName $computerName -Credential $creds

# Elasticsearch server URL
$elasticsearchUrl = "https://10.109.35.100:9200"

# Index name
$indexName = "hap-groupmembers"

# Elasticsearch credentials
$elasticUsername = 'elastic'
$elasticPassword = 'Fy590f0TI7Wg7L0MO4Og44gd' # Password is on the TFPlenum home page

# Create Elasticsearch Credential Object
[SecureString]$elasticSecureString = ConvertTo-SecureString -String $elasticPassword -AsPlainText -Force
[PSCredential]$elasticCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $elasticUsername, $elasticSecureString

# Set SSL certificate validation callback
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Create the Elasticsearch document endpoint URL
$documentUrl = "$elasticsearchUrl/$indexName/_doc"

# Loop through each group member, convert to JSON, and send to Elasticsearch
foreach ($groupMember in $groupMembersData) {
    $groupMemberObj = @{
        "groupMember" = $groupMember
    }

    $jsonData = $groupMemberObj | ConvertTo-Json

    # Send the JSON data as the request body to create the document
    Invoke-RestMethod -Method 'POST' -Uri $documentUrl -Body $jsonData -ContentType 'application/json' -Credential $elasticCredentials
}


# SHARES
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
        If (!$Credential) {
            $Credential = Get-Credential
        }
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            foreach ($share in (Get-SmbShare).Name) {
                Get-SmbShareAccess $share
            } 
        }
    }    
}

# Change creds as needed
$username = 'Administrator'
$password = 'P@55w0rd!'

# Create Credential Object
[SecureString]$secureString = $password | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureString

# Specify the target computer name
$computerName = "10.136.36.54"

# Retrieve share information using Get-ShareInfo function
$shareInfo = Get-ShareInfo -ComputerName $computerName -Credential $creds

# Elasticsearch server URL
$elasticsearchUrl = "https://10.109.35.100:9200"

# Index name
$indexName = "hap-shares"

# Elasticsearch credentials
$elasticUsername = 'elastic'
$elasticPassword = 'Fy590f0TI7Wg7L0MO4Og44gd' # Password is on the TFPlenum home page

# Create Elasticsearch Credential Object
[SecureString]$elasticSecureString = ConvertTo-SecureString -String $elasticPassword -AsPlainText -Force
[PSCredential]$elasticCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $elasticUsername, $elasticSecureString

# Set SSL certificate validation callback
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Create the Elasticsearch document endpoint URL
$documentUrl = "$elasticsearchUrl/$indexName/_doc"

# Loop through each share information, convert to JSON, and send to Elasticsearch
foreach ($share in $shareInfo) {
    $shareObj = @{
        "share" = $share
    }

    $jsonData = $shareObj | ConvertTo-Json

    # Send the JSON data as the request body to create the document
    Invoke-RestMethod -Method 'POST' -Uri $documentUrl -Body $jsonData -ContentType 'application/json' -Credential $elasticCredentials
}


# LOGON HISTORY
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
        If (!$Credential) {
            $Credential = Get-Credential
        }
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $loggedOnUsers = Get-WmiObject win32_loggedonuser
            $sessions = Get-WmiObject win32_logonsession
            $logons = @()

            foreach ($user in $loggedOnUsers)
            {
                $user.Antecedent -match '.+Domain="(.+)",Name="(.+)"$' > $null
                $domain = $matches[1]
                $username = $matches[2]
    
                $user.Dependent -match '.+LogonId="(\d+)"$' > $null
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

# Change creds as needed
$username = 'Administrator'
$password = 'P@55w0rd!'

# Create Credential Object
[SecureString]$secureString = $password | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureString

# Specify the target computer name
$computerName = "10.136.36.54"

# Retrieve logon history using Get-LogOnHistory function
$logonHistory = Get-LogOnHistory -ComputerName $computerName -Credential $creds

# Elasticsearch server URL
$elasticsearchUrl = "https://10.109.35.100:9200"

# Index name
$indexName = "hap-logonhistory"

# Elasticsearch credentials
$elasticUsername = 'elastic'
$elasticPassword = 'Fy590f0TI7Wg7L0MO4Og44gd' # Password is on the TFPlenum home page

# Create Elasticsearch Credential Object
[SecureString]$elasticSecureString = ConvertTo-SecureString -String $elasticPassword -AsPlainText -Force
[PSCredential]$elasticCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $elasticUsername, $elasticSecureString

# Set SSL certificate validation callback
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Create the Elasticsearch document endpoint URL
$documentUrl = "$elasticsearchUrl/$indexName/_doc"

# Loop through each logon history, convert to JSON, and send to Elasticsearch
foreach ($logon in $logonHistory) {
    $logonObj = @{
        "logon" = $logon
    }

    $jsonData = $logonObj | ConvertTo-Json

    # Send the JSON data as the request body to create the document
    Invoke-RestMethod -Method 'POST' -Uri $documentUrl -Body $jsonData -ContentType 'application/json' -Credential $elasticCredentials
}


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
        If (!$Credential) {
            $Credential = Get-Credential
        }
    }

    Process
    {
        $local_path = ($env:USERPROFILE + '\AppData\Local\Temp\XML\') # directory where XML files will be stored on your machine
        $export_path = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {"$env:USERPROFILE\AppData\Local\Temp\" + $env:COMPUTERNAME + "-events.xml"} # Directory where xml file will be saved on endpoint

        if (-not (Test-Path -Path $local_path -PathType Container)) {
            New-Item -Path ($env:USERPROFILE + '\AppData\Local\Temp') -Name XML -ItemType Directory
        } # create the dir if it doesn't exist

        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $events = foreach ($event in $using:EventList) {
                Get-WinEvent -FilterHashtable @{
                    LogName    = $event.Event_Log
                    StartTime  = $using:BeginTime
                    EndTime    = $using:EndTime
                    Id         = $event.ID
                } -ErrorAction Ignore
            }

            $events | Export-Clixml -Path $using:export_path
        }

        # PSSession to pull the file back
        $session = New-PSSession -ComputerName $ComputerName -Credential $Credential

        # Copy the file from the remote machine to your local machine
        Copy-Item -Path $export_path -Destination $local_path -FromSession $session

        # Remove event log from the remote machine
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            Remove-Item -Path $using:export_path
        }

        # Elasticsearch server URL
        $elasticsearchUrl = "https://10.109.35.100:9200"

        # Index name
        $indexName = "hap-eventlogs"

        # Elasticsearch credentials
        $elasticUsername = 'elastic'
        $elasticPassword = 'Fy590f0TI7Wg7L0MO4Og44gd' # Password is on the TFPlenum home page

        # Create Elasticsearch Credential Object
        [SecureString]$elasticSecureString = ConvertTo-SecureString -String $elasticPassword -AsPlainText -Force
        [PSCredential]$elasticCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $elasticUsername, $elasticSecureString

        # Create the Elasticsearch document endpoint URL
        $documentUrl = "$elasticsearchUrl/$indexName/_doc"

        # Loop through each XML file, convert to JSON, and send to Elasticsearch
        $xmlFiles = Get-ChildItem -Path $local_path -Filter "*-events.xml"

        foreach ($file in $xmlFiles) {
            $xmlData = Import-Clixml -Path $file.FullName

            foreach ($event in $xmlData) {
                $eventObj = @{
                    "event" = $event
                }

                $jsonData = $eventObj | ConvertTo-Json

                # Ignore SSL certificate validation
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

                # Send the JSON data as the request body to create the document
                Invoke-RestMethod -Method 'POST' -Uri $documentUrl -Body $jsonData -ContentType 'application/json' -Credential $elasticCredentials
            }
        }
    }
}


