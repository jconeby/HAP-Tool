﻿# Processes
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

<# Example

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

<#
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

<# Example

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


<# Example

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

<# Example

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

<# Example

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

<# Example

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


#>


# Registry Run Keys
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
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            # Define registry run keys
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

            $registryRunData = foreach ($runKey in $registryRunKeys) {
                $key = $runKey.Key
                $description = $runKey.Description
                if (Test-Path $key) {
                    Get-ItemProperty -Path $key | Select-Object -Property *, @{Name = 'Description'; Expression = {$description}}, @{Name = 'Time'; Expression = {(Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")}}
                }
            }

            $registryRunData
        } 
    }
}

<# Example

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

#>


# Startup Folders
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
                Path        = ($env:APPDATA) + '\Microsoft\Windows\Start Menu\Programs\Startup'
                Description = "User Startup Folder"
            }
            @{
                Path        = ($env:ProgramData) + '\Microsoft\Windows\Start Menu\Programs\Startup'
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

<# Example

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
#>

# Local Users
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

<# Example

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


#>

# Local Groups
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

<# Example

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

<# Example

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

<# Example

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

<# Example
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
#>

#>


# Exports Event Log

function Get-CriticalEventXML
{ 
    [cmdletbinding()]
    Param
    (

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


        # List of Event IDs to capture
            $eventIDs = @(
                [PSCustomObject]@{
                    Event_Log = 'Security'
                    ID = 4624
                },
                [PSCustomObject]@{
                    Event_Log = 'Security'
                    ID = 4634
                },
                [PSCustomObject]@{
                    Event_Log = 'Security'
                    ID = 4688
                },
                [PSCustomObject]@{
                    Event_Log = 'Security'
                    ID = 4698
                },
                [PSCustomObject]@{
                    Event_Log = 'Security'
                    ID = 4702
                },
                [PSCustomObject]@{
                    Event_Log = 'Security'
                    ID = 4740
                },
                [PSCustomObject]@{
                    Event_Log = 'Security'
                    ID = 4625
                },
                [PSCustomObject]@{
                    Event_Log = 'Security'
                    ID = 5152
                },
                [PSCustomObject]@{
                    Event_Log = 'Security'
                    ID = 5154
                },
                [PSCustomObject]@{
                    Event_Log = 'Security'
                    ID = 5155
                },
                [PSCustomObject]@{
                    Event_Log = 'Security'
                    ID = 5156
                },
                [PSCustomObject]@{
                    Event_Log = 'Security'
                    ID = 5157
                },
                [PSCustomObject]@{
                    Event_Log = 'Security'
                    ID = 4648
                },
                [PSCustomObject]@{
                    Event_Log = 'Security'
                    ID = 4672
                },
                [PSCustomObject]@{
                    Event_Log = 'Security'
                    ID = 4673
                },
                [PSCustomObject]@{
                    Event_Log = 'Security'
                    ID = 4769
                },
                [PSCustomObject]@{
                    Event_Log = 'Security'
                    ID = 4771
                },
                [PSCustomObject]@{
                    Event_Log = 'Security'
                    ID = 5140
                }
            )


        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            
            $events = foreach ($event in $using:eventIDs) {
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

     }
}

<# Example
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
#>


# Enrich Events -- This is meant to have event objects passed to it
function Update-EventList {
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

function Index-Data {
    param (
        [Parameter(Mandatory=$true)]
        [string]$elasticURL,
        
        [Parameter(Mandatory=$true)]
        [string]$indexName,
        
        [Parameter(Mandatory=$true)]
        [string]$category,
        
        [Parameter(Mandatory=$true)]
        [array]$dataArray
    )

    # Create the Elasticsearch document endpoint URL
    $documentUrl = "$elasticURL/$indexName/_doc"

    # Iterate over the data array
    foreach ($dataItem in $dataArray) {
        $data = @{
            $category = $dataItem
        }

        # Convert the data to JSON
        $jsonData = $data | ConvertTo-Json

        # Ignore SSL certificate validation
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

        # Send the JSON data as the request body to create the document
        Invoke-RestMethod -Method 'POST' -Uri $documentUrl -Body $jsonData -ContentType 'application/json'
    }
}
