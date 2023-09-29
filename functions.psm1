#----------------------------- PROCESSES-------------------------------
function Get-WmiProcess {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        [string[]]
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
        $processes = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $processes = Get-WmiObject win32_Process
            $processLookup = @{}

            # Create a lookup table for process IDs and names
            foreach ($process in $processes) {
                $processLookup[$process.ProcessID] = $process.Name
            }

            $results = @()

            foreach ($process in $processes) {
                $parentProcessID = $process.ParentProcessID
                $parentProcessName = $processLookup[$parentProcessID] -as [string]

                $grandparentProcessName = $null
                $grandparentProcessID = $null

                if ($parentProcessName) {
                    $grandparentProcessID = (Get-WmiObject win32_Process -Filter "ProcessID = $parentProcessID" |
                        Select-Object -ExpandProperty ParentProcessID) -as [uint32]

                    if ($grandparentProcessID -ne 0) {
                        $grandparentProcessName = $processLookup[$grandparentProcessID] -as [string]
                    }
                }

                $lineageHash = [System.Security.Cryptography.MD5]::Create().ComputeHash(
                    [System.Text.Encoding]::UTF8.GetBytes("$grandparentProcessName|$parentProcessName|$($process.Name)")
                )
                $lineageHashString = [System.BitConverter]::ToString($lineageHash).Replace("-", "")

                $results += [PSCustomObject]@{
                    "CSName"                 = $process.CSName
                    "ProcessName"            = $process.Name
                    "ProcessID"              = $process.ProcessID
                    "ParentProcessName"      = $parentProcessName
                    "ParentProcessID"        = $parentProcessID
                    "GrandParentProcessName" = $grandparentProcessName
                    "GrandParentProcessID"   = $grandparentProcessID
                    "HandleCount"            = $process.HandleCount
                    "ThreadCount"            = $process.ThreadCount
                    "Path"                   = $process.Path
                    "CommandLine"            = $process.CommandLine
                    "PSComputerName"         = $process.PSComputerName
                    "RunspaceId"             = $process.RunspaceId
                    "PSShowComputerName"     = $true
                    "Time"                   = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                    "UTCTime"                = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                    "LineageHash"            = $lineageHashString
                }
            }

            $results
        }

        $processes
    }
}


#------------------------------------- SERVICES---------------------------------------------------
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
                    "CSName"             = $_.SystemName
                    "PSComputerName"     = $_.PSComputerName
                    "ServiceName"        = $_.Name
                    "ServiceState"       = $_.State
                    "SystemName"         = $_.SystemName
                    "ServiceDisplayName" = $_.DisplayName
                    "ServiceDescription" = $_.Description
                    "PathName"           = $_.PathName
                    "InstallDate"        = $_.InstallDate
                    "ProcessId"          = $_.ProcessId
                    "ProcessName"        = (Get-WmiObject -Class Win32_Process -Filter "ProcessId='$($_.ProcessId)'").Name
                    "ParentProcessID"    = (Get-WmiObject -Class Win32_Process -Filter "ProcessId='$($_.ProcessId)'").ParentProcessID
                    "ParentProcessName"  = (Get-Process -ID (Get-WmiObject -Class Win32_Process -Filter "ProcessId='$($_.ProcessId)'").ParentProcessID).Name
                    "StartMode"          = $_.StartMode
                    "ExitCode"           = $_.ExitCode
                    "DelayedAutoStart"   = $_.DelayedAutoStart
                    "Time"               = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                    "UTCTime"            = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                }
            }
        }
        $services
    }
} 


#------------------------------------------- CONNECTIONS-------------------------------------------------
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
                    PSComputerName   = $connection.PSComputerName
                    CSName           = $process.CSName
                    LocalAddress     = $connection.LocalAddress
                    LocalPort        = $connection.LocalPort
                    RemoteAddress    = $connection.RemoteAddress
                    RemotePort       = $connection.RemotePort
                    State            = $connection.State
                    OwningProcess    = $connection.OwningProcess
                    ProcessName      = $process.Name
                    ProcessID        = $process.ProcessId
                    ParentProcessID  = $parentProcess.ProcessID
                    ParentProcess    = $parentProcess.Name
                    CreationTime     = $connection.CreationTime
                    Time             = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                    UTCTime          = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                }
            }
        }
        $connections
    }
}


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
                    CSName          = $env:COMPUTERNAME
                    PSComputerName  = $task.PSComputerName
                    TaskName        = $task.TaskName
                    Author          = $task.Author
                    Date            = $task.Date
                    URI             = $task.URI
                    State           = $task.State
                    TaskPath        = $task.TaskPath
                    LastRunTime     = $taskinfo.LastRunTime
                    LastRunTimeUTC  = ($taskinfo.LastRunTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                    LastTaskResult  = $taskinfo.LastTaskResult
                    NextRunTime     = $taskinfo.NextRunTime
                    Time            = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                    UTCTime         = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                }
            }
            $taskInfoList
        }

        $tasks
    }    
}


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
        If (!$Credential) { $Credential = Get-Credential }
    }
    Process
    {   
        $prefetchData = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $pfconf = (Get-ItemProperty "hklm:\system\currentcontrolset\control\session manager\memory management\prefetchparameters").EnablePrefetcher 

            Switch -Regex ($pfconf) {
                "[1-3]" {
                    $prefetches = ls $env:windir\Prefetch\*.pf | ForEach-Object {
                        $processName = $_.Name -replace '-.*$'

                        [PSCustomObject]@{
                            CSName             = $env:COMPUTERNAME
                            FullName           = $_.FullName
                            CreationTimeUtc    = $_.CreationTimeUtc.ToString("o")
                            LastAccessTimeUtc  = $_.LastAccessTimeUtc.ToString("o")
                            LastWriteTimeUtc   = $_.LastWriteTimeUtc.ToString("o")
                            Time               = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                            UTCTime            = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                            ProcessName        = $processName
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
                "CSName"                 = $_.CSName
                "OperatingSystem"        = $_.Caption
                "OperatingSystemVersion" = $_.Version
                "Manufacturer"           = $_.Manufacturer
                "RegisteredOwner"        = $_.RegisteredUser
                "InstallDate"            = $_.InstallDate.ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                "LastBootTime"           = $_.LastBootUpTime.ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                "SerialNumber"           = $_.SerialNumber
                "Time"                   = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                "UTCTime"                = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
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
            $registryRunKeys = @(
                'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
                'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
                'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce',
                'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce',
                'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices',
                'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices'
            )

            $registryRunData = foreach ($keyPath in $registryRunKeys) {
                $keyName = $keyPath -replace '^.+\\'

                if (Test-Path $keyPath) {
                    $keyValues = Get-ItemProperty -Path $keyPath | Select-Object -Property *
                    
                    foreach ($valueName in $keyValues.PSObject.Properties.Name) {
                        $valueData = $keyValues.$valueName
                        
                        # Check if the value is a program configured for startup
                        if ($valueData -match '^.+\.exe') {
                            $processName = [regex]::Match($valueData, '[^\\/]+(?=\.exe)').Value
                            
                            if ([string]::IsNullOrEmpty($processName)) {
                                $processName = [io.path]::GetFileNameWithoutExtension($valueData)
                            }
                            
                            $keyName | Select-Object -Property @{Name = 'KeyName'; Expression = {$_}}, @{Name = 'Details'; Expression = {$valueData}}, @{Name = 'ProcessName'; Expression = {$processName}}, @{Name = 'Time'; Expression = {(Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")}}
                        }
                    }
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

function Get-RegistryUserShellFolders {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
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
            $shellFoldersKeys = @(
                'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders',
                'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
            )

            $shellFoldersData = foreach ($keyPath in $shellFoldersKeys) {
                if (Test-Path $keyPath) {
                    $keyValues = Get-ItemProperty -Path $keyPath | Select-Object -Property *
                    $keyName = $keyPath -replace '^.+\\'

                    foreach ($valueName in $keyValues.PSObject.Properties.Name) {
                        $valueData = $keyValues.$valueName
                        [PSCustomObject]@{
                            Key         = $keyName
                            ValueName   = $valueName
                            ValueData   = $valueData
                            Time        = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
                        }
                    }
                }
            }

            $shellFoldersData
        }
    }
}


# Change creds as needed
$username = 'Administrator'
$password = '8LegsOnTheSpider!'

# Create Credential Object for Windows creds
[SecureString]$secureString = $password | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$Credential = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureString


# Change the ComputerNames or IP addresses as needed
$ComputerName = 'localhost'
 
# Gather registry run data
$registry = Get-RegistryUserShellFolders -ComputerName $ComputerName -Credential $Credential


# Startup Folders
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
        $startupData = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
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
                                CSName                   = $env:COMPUTERNAME
                                StartupFolderPath        = $file.DirectoryName
                                StartupFolderDescription = $folder.Description
                                FileInfoName             = $fileInfo.Name
                                FileInfoSize             = $fileInfo.Length
                                LastWriteTime            = $fileInfo.LastWriteTime.ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                                LastWriteTimeUTC         = $fileInfo.LastWriteTime.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
                                Time                     = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                                UTCTime                  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
                                Hash                     = (Get-FileHash -Path $file.FullName -Algorithm SHA1).Hash

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
                    "CSName"                      = $env:COMPUTERNAME
                    "LocalUserName"               = $_.Name
                    "LocalUserSID"                = $_.SID
                    "LocalUserStatus"             = $_.Status
                    "LocalUserAccountType"        = $_.AccountType
                    "LocalUserCaption"            = $_.Caption
                    "LocalUserDescription"        = $_.Description
                    "LocalUserDomain"             = $_.Domain
                    "LocalUserDisabled"           = $_.Disabled
                    "LocalAccount"                = $_.LocalAccount
                    "LocalUserLockout"            = $_.Lockout
                    "LocalUserPasswordChangeable" = $_.PasswordChangeable
                    "LocalUserPasswordExpires"    = $_.PasswordExpires
                    "LocalUserPasswordRequired"   = $_.PasswordRequired
                    "LocalUserSIDType"            = $_.SIDType
                    "LocalUserFullName"           = $_.FullName
                    "LocalUserAccountExpires"     = $_.AccountExpires
                    "Time"                        = (Get-Date).ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
                    "UTCTime"                     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
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
                "CSName"                 = $env:COMPUTERNAME
                "LocalGroupName"         = $_.Name
                "LocalGroupSID"          = $_.SID
                "LocalGroupDomain"       = $_.Domain
                "LocalGroupCaption"      = $_.Caption
                "LocalGroupDescription"  = $_.Description
                "LocalGroupLocalAccount" = $_.LocalAccount
                "LocalGroupSIDType"      = $_.SIDType
                "Time"                   = (Get-Date).ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
                "UTCTime"                = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")

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
                        CSName    = $env:COMPUTERNAME
                        GroupName = $name 
                        Member    = (Get-LocalGroupMember $name)
                        Time      = (Get-Date).ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'") 
                        UTCTime   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")   
                                                        
                    }
                }
            }
            catch
            {
                foreach ($name in (Get-WmiObject -Class Win32_Group).Name) {
                    [PSCustomObject]@{
                        CSName    = $env:COMPUTERNAME
                        GroupName = $name 
                        Member    = Get-WmiObject win32_groupuser | Where-Object {$_.groupcomponent -like "*$name*"} | ForEach-Object {  
                            $_.partcomponent –match ".+Domain\=(.+)\,Name\=(.+)$" > $null  
                            $matches[1].trim('"') + "\" + $matches[2].trim('"')  
                        }
                        Time      = (Get-Date).ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'") 
                        UTCTime   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")    
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
    [CmdletBinding()]
    Param
    (
        [Parameter(ValueFromPipeline = $true)]
        [string[]]
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
            foreach ($share in (Get-SmbShare).Name) {
                $accessInfo = Get-SmbShareAccess $share
                $accessInfo | Add-Member -NotePropertyName "Time" -NotePropertyValue (Get-Date).ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
                $accessInfo
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

                $startTime = [DateTime]::ParseExact($session.StartTime.Substring(0, 14), "yyyyMMddHHmmss", $null)

                [PSCustomObject]@{
                    CSName        = $env:COMPUTERNAME
                    LogonId       = $session.LogonId
                    LogonTypeId   = $session.LogonType
                    LogonType     = $logonType
                    LogonDomain   = ($logons | Where-Object { $_.LogonId -eq $session.LogonId }).Domain
                    LogonUser     = ($logons | Where-Object { $_.LogonId -eq $session.LogonId }).User
                    StartTime     = $session.StartTime
                    StartTimeUTC  = $startTime.ToUniversalTime()
                    Time          = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
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
       
        if (-not (Test-Path -Path $local_path -PathType Container)) {
            New-Item -Path ($env:USERPROFILE + '\AppData\Local\Temp') -Name XML -ItemType Directory
        } # create the dir if it doesn't exist

        $num = 0 # Used to make sure there is a unique name for each file created

        foreach ($computer in $ComputerName) {
             $num++
             $temp_path = Invoke-Command -ComputerName $computer -Credential $Credential -ScriptBlock {Join-Path -Path $env:USERPROFILE -ChildPath 'temp'}
             $hostname = Invoke-Command -ComputerName $computer -Credential $Credential -ScriptBlock {hostname}
             $filename = ($hostname + '-' + $num.ToString() + '-events.xml')
             $export_path = ($temp_path + '\' + $filename) # path where the XML file will be exported on the endpoint

                Invoke-Command -ComputerName $computer -Credential $Credential -ScriptBlock {

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
                        },
                        [PSCustomObject]@{
                            Event_Log = 'Security'
                            ID = 1102
                        }
                    )

            
                    $events = foreach ($event in $eventIDs) {
                        Get-WinEvent -FilterHashtable @{
                            LogName    = $event.Event_Log
                            StartTime  = $using:BeginTime
                            EndTime    = $using:EndTime
                            Id         = $event.ID
                        } -ErrorAction Ignore
                    }


                    # Create export directory if it doesn't exist
                     if (-not (Test-Path -Path $using:temp_path -PathType Container)) {
                                                         New-Item -ItemType Directory -Path $using:temp_path -Force
                                                                   }
                     

                   $events | Export-Clixml -Path $using:export_path -Force 

                } # End of Invoke Command

                # PSSession to pull the file back
                $session = New-PSSession -ComputerName $computer -Credential $Credential

                # Copy the file from the remote machine to your local machine
                Copy-Item -Path $export_path -Destination $local_path -FromSession $session

                # Remove event log from the remote machine
                Invoke-Command -ComputerName $computer -Credential $Credential -ScriptBlock {
                    Remove-Item -Path $using:export_path
                }

             } # End of Invoke Command

          

             } # End of Primary For Loop
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
function Enrich-Event {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [Array]
        $Events
    )

    Process {
        foreach ($event in $Events) {
            $eventMessage = $event.Message

            # Regular expressions to extract field values
            $accountNamePattern = "Account Name:\s+(.+)"
            $accountDomainPattern = "Account Domain:\s+(.+)"
            $logonIDPattern = "Logon ID:\s+(0x[A-Fa-f0-9]+)"
            $logonTypePattern = "Logon Type:\s+(.+)"
            $processIDPattern = "Process ID:\s+0x([A-Fa-f0-9]+)\b"
            $processNamePattern = "Process Name:\s+(.+)"
            $workstationNamePattern = "Workstation Name:\s+(.+)"
            $sourceNetworkAddressPattern = "Source Network Address:\s+(.+)"
            $sourcePortPattern = "Source Port:\s+(.+)"
            $logonProcessPattern = "Logon Process:\s+(.+)"
            $parentProcessPattern = "Creator Process Name:\s+(.+)"
            $parentProcessIDPattern = "Creator Process ID:\s+0x([A-Fa-f0-9]+)\b"

            # Extract field values using regular expressions
            $accountName = [regex]::Match($eventMessage, $accountNamePattern).Groups[1].Value
            $accountDomain = [regex]::Match($eventMessage, $accountDomainPattern).Groups[1].Value
            $logonIDHexMatch = [regex]::Match($eventMessage, $logonIDPattern)
            $logonIDHex = $logonIDHexMatch.Groups[1].Value
            $logonType = [regex]::Match($eventMessage, $logonTypePattern).Groups[1].Value
            $processIDHexMatch = [regex]::Match($eventMessage, $processIDPattern)
            $processIDHex = $processIDHexMatch.Groups[1].Value
            $processPath = [regex]::Match($eventMessage, $processNamePattern).Groups[1].Value
            $workstationName = [regex]::Match($eventMessage, $workstationNamePattern).Groups[1].Value
            $sourceNetworkAddress = [regex]::Match($eventMessage, $sourceNetworkAddressPattern).Groups[1].Value
            $sourcePort = [regex]::Match($eventMessage, $sourcePortPattern).Groups[1].Value
            $logonProcess = [regex]::Match($eventMessage, $logonProcessPattern).Groups[1].Value
            $parentProcessPath = [regex]::Match($eventMessage, $parentProcessPattern).Groups[1].Value
            $parentProcessIDHexMatch = [regex]::Match($eventMessage, $parentProcessIDPattern)
            $parentProcessIDHex = $parentProcessIDHexMatch.Groups[1].Value


            # Convert LogonID from hexadecimal to decimal
            $logonID = 0
            if ($logonIDHexMatch.Success) {
                $logonID = [bigint]::Parse($logonIDHex.Substring(2), 'HexNumber')
            }

            # Convert ProcessID from hexadecimal to decimal
            $processID = 0
            if ($processIDHexMatch.Success) {
                $processID = [convert]::ToInt32($processIDHex, 16)
            }

            # Convert ParentProcessID from hexadecimal to decimal
            $parentProcessID = 0
            if ($parentProcessIDHexMatch.Success) {
                $parentProcessID = [convert]::ToInt32($parentProcessIDHex, 16)
            }

            # EventID to Description Mapping
            $EventIdDescriptionMapping = @{
            4624 = "An account was successfully logged on."
            4634 = "An account was logged off."
            4688 = "A new process has been created."
            4698 = "A scheduled task was created."
            4702 = "A scheduled task was updated."
            4740 = "A user account was locked out."
            4625 = "An account failed to log on."
            5152 = "The Windows Filtering Platform blocked a packet."
            5154 = "The Windows Filtering Platform has permitted an application or service to listen on a port for incoming connections."
            5155 = "The Windows Filtering Platform has blocked an application or service from listening on a port for incoming connections."
            5156 = "The Windows Filtering Platform has allowed a connection."
            5157 = "The Windows Filtering Platform has blocked a connection."
            4648 = "A logon was attempted using explicit credentials."
            4672 = "Special privileges assigned to a new logon."
            4673 = "A privileged service was called."
            4769 = "A Kerberos service ticket was requested."
            4771 = "Kerberos pre-authentication failed."
            5140 = "A network share object was accessed."
            1102 = "The audit log was cleared."
        }

            # Create custom object with the extracted field values
            $eventData = [PSCustomObject]@{
                CSName               = $event.MachineName
                Id                   = $event.Id
                TimeCreated          = $event.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                UTCTimeCreated       = $event.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                Description          = $EventIdDescriptionMapping[$event.Id]
                MachineName          = $event.MachineName
                RecordId             = $event.RecordId
                Time                 = (Get-Date).ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
                Message              = $event.Message
                AccountName          = $accountName
                AccountDomain        = $accountDomain
                LogonID              = $logonID
                LogonType            = $logonType
                ProcessID            = $processID
                ProcessName          = if($ProcessPath) {Split-Path $ProcessPath -Leaf} else {$null}
                ProcessPath          = $processPath
                ParentProcessID      = $parentProcessID
                ParentProcessName    = if($ParentProcessPath) {Split-Path $ParentProcessPath -Leaf} else {$null}
                ParentProcessPath    = $parentProcessPath
                WorkstationName      = $workstationName
                SourceNetworkAddress = $sourceNetworkAddress
                SourcePort           = $sourcePort
                LogonProcess         = $logonProcess
            }

            $eventData
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


# Test if WinRM and Invoke Command will work on an array of computers
function Test-ComputerConnection {
    param (
        [Parameter(ValueFromPipeline = $true)]
        [string[]]
        $ComputerNames,

        [PSCredential]
        $Credential
    )

    Begin {
        If (!$Credential) {
            $Credential = Get-Credential
        }
    }

    Process {
        foreach ($computer in $ComputerNames) {
            $winrmEnabled = $false
            $ready = $false
            try {
                $winrmStatus = Invoke-Command -ComputerName $computer -Credential $Credential -ScriptBlock { Test-WSMan } -ErrorAction Stop
                if ($winrmStatus) {
                    $winrmEnabled = $true
                }
            } catch {
                $winrmEnabled = $false
            }

            if ($winrmEnabled) {
                Write-Host "WinRM is enabled and can connect to $computer"
                $ready = $true
            } else {
                Write-Host "WinRM is not enabled or cannot connect to $computer"
                $ready = $false
            }
        }

        return $ready
    }
}


function Index-Data {
    param (
        [Parameter(Mandatory=$true)]
        [string]$elasticURL,

        [Parameter(Mandatory=$true)]
        [pscredential]$Credential,
        
        [Parameter(Mandatory=$true)]
        [string]$indexName,
        
        [Parameter(Mandatory=$true)]
        [array]$dataArray
    )

    # Create the Elasticsearch document endpoint URL
    $documentUrl = "$elasticURL/$indexName/_doc"

    # Iterate over the data array
    foreach ($dataItem in $dataArray) {
        $data = @{
            'hap' = $dataItem
        }

        # Convert the data to JSON
        $jsonData = $data | ConvertTo-Json

        # Ignore SSL certificate validation
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

        # Send the JSON data as the request body to create the document
        Invoke-RestMethod -Method 'POST' -Uri $documentUrl -Body $jsonData -ContentType 'application/json' -Credential $Credential
       
    }
}

# Function to create index patterns in Elastic
function Create-IndexPattern {
    param (
        [Parameter(Mandatory=$true)]
        [string]$elasticURL,

        [Parameter(Mandatory=$true)]
        [pscredential]$Credential,
        
        [Parameter(Mandatory=$true)]
        [string]$indexPattern
       
    )

     # Set the index pattern definition
        $index_payload = @{
            "title" = $indexPattern
            "timeFieldName" = "hap.Time"
        }

        # Convert the index pattern definition to JSON
        $indexPayloadJson = $index_payload | ConvertTo-Json

        $data = @{
            'type' = 'index-pattern'
            'index-pattern' = @{
                'title' = $indexPattern
                'timeFieldName' = 'hap.Time'
            }
        }

        # Convert the data to JSON
        $jsonData = $data | ConvertTo-Json

        # Set the Kibana API endpoint for creating index patterns
        $IndexPatternEndpoint = "$elasticURL/.kibana/_doc/index-pattern:$indexPattern"

        # Invoke the API to create the index pattern
        $response = Invoke-RestMethod -Method 'POST' -Uri $IndexPatternEndpoint -Body $jsonData -ContentType 'application/json' -Credential $Credential

        return $response

}

function Split-StringWithComma {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [String]$InputString
    )

    process {
        if ($InputString -match ',') {
            $InputString -split ','
        } else {
            $InputString
        }
    }
}

function Remove-Spaces {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [String]$InputString
    )

    process {
        $InputString -replace '\s', ''
    }
}

#-----------------------------INVENTORY DOMAIN CONTROLLERS--------------------------------------------------
function Get-DomainController {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        [string[]]
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
           $domainControllers = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                $domainControllers = ([adsisearcher]'(&(objectCategory=computer)(primaryGroupID=516))').FindAll() | ForEach-Object { 
                    $properties = $_.Properties
                    [PSCustomObject]@{
                        Name                  = $properties["name"] -as [string]
                        DNShostname           = $properties["dnshostname"] -as [string]
                        OperatingSystem       = $properties["operatingsystem"] -as [string]
                        OperatingSystemVersion = $properties["operatingsystemversion"] -as [string]
                        LastLogonTimestamp    = [datetime]::FromFileTime($properties["lastlogontimestamp"][0]).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                        DistinguishedName     = $properties["distinguishedname"] -as [string]
                        Time                   = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                        UTCTime                = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                    }
                }

                $domainControllers
           }
           $domainControllers
    }
}

#-------------------------------PROTECTED GROUP MEMBERS--------------------------------------------------------------------
function Get-ProtectedUsers {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        [string[]]
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
           $protected_users = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {

                    $searcher = [adsisearcher]'(&(objectClass=user)(adminCount=1))'

                    # Specify the properties you want to retrieve
                    $searcher.PropertiesToLoad.AddRange(@('sAMAccountName', 'distinguishedName', 'logonCount', 'description', 'badPasswordTime', 'pwdLastSet', 'lastlogontimestamp', 'whenCreated', 'whenChanged', 'adminCount'))

                    # Execute the search
                    $results = $searcher.FindAll()

                    $protected_users = @()

                            # Loop through the results
                            foreach ($result in $results) {
                                $properties = $result.Properties
                                $protected_users += [PSCustomObject]@{
                                    Username           = $properties['samaccountname'] -as [string]
                                    DistinguishedName  = $properties['distinguishedname'] -as [string]
                                    LogonCount         = $properties['logoncount'] -as [string]
                                    Description        = $properties['description'] -as [string]
                                    BadPasswordTime    = [datetime]::FromFileTime($properties['badpasswordtime'][0] -as [long]).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                                    PwdLastSet         = [datetime]::FromFileTime($properties['pwdlastset'][0] -as [long]).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                                    LastLogonTimestamp = [datetime]::FromFileTime($properties['lastlogontimestamp'][0] -as [long]).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                                    WhenCreated        = $properties['whencreated'][0] -as [string]
                                    WhenChanged        = $properties['whenchanged'][0] -as [string]
                                    AdminCount         = $properties['admincount'][0] -as [string]
                                    Time               = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                                    UTCTime            = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                                }
                            }
                    $protected_users
                }
            $protected_users
    }
}


#-------------------AD USERS----------------------------------------------
function Get-DomainUser {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        [string[]]
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
        $users = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                $searcher = [adsisearcher]"(&(objectCategory=user)(objectClass=user))"

                # Specify the properties to retrieve
                $searcher.PropertiesToLoad.AddRange(@('samaccountname', 'name', 'instancetype', 'userprincipalname', 'logoncount',
                'description', 'pwdlastset', 'badpwdcount', 'lastlogontimestamp', 'memberof', 'whencreated', 'adspath', 'cn', 'primarygroupid',
                'distinguishedname', 'admincount'))

                # Execute the search
                $results = $searcher.FindAll()

                # Define the number of days of inactivity
                $daysInactive = 30

                # Calculate the lastLogonTimestamp of the $daysInactive
                $inactiveTime = (Get-Date).AddDays(-$daysInactive).ToFileTime()

                $users = foreach ($result in $results) {
                    $properties = $result.Properties
                    
                    $lastLogonTimestamp = if ($properties['lastlogontimestamp']) {
                        [datetime]::FromFileTime([long]$properties['lastlogontimestamp'][0]).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                    }

                    $pwdLastSet = if ($properties['pwdlastset']) {
                        [datetime]::FromFileTime([long]$properties['pwdlastset'][0])
                    }

                    [PSCustomObject]@{
                        Username            = $properties['samaccountname'] -as [string]
                        Name                = $properties['name'] -as [string]
                        InstanceType        = $properties['instancetype'] -as [string]
                        UserPrincipalName   = $properties['userprincipalname'] -as [string]
                        LogonCount          = $properties['logoncount'] -as [string]
                        Description         = $properties['description'] -as [string]
                        PwdLastSet          = $pwdLastSet
                        BadPwdCount         = $properties['badpwdcount'] -as [string]
                        LastLogonTimestamp  = $lastLogonTimestamp
                        MemberOf            = $properties['memberof'] -join '; '  # Convert string array to semicolon-separated string
                        WhenCreated         = $properties['whencreated'] -as [string]
                        ADsPath             = $properties['adspath'] -as [string]
                        CN                  = $properties['cn'] -as [string]
                        PrimaryGroupId      = $properties['primarygroupid'] -as [string]
                        DistinguishedName   = $properties['distinguishedname'] -as [string]
                        AdminCount          = $properties['admincount'] -as [string]
                        Inactive            = if ($lastLogonTimestamp) { $lastLogonTimestamp -lt [datetime]::FromFileTime($inactiveTime) } else { $null }
                        Time                = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                        UTCTime             = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                    }
                }
                $users
        }
        $users
    }
    
}

#-------------------------AD GROUPS------------------------------------------
function Get-DomainGroup {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        [string[]]
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
        $groups = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                # Define the LDAP query string to find all groups
                $searcher = [adsisearcher]"(objectCategory=group)"

                # Specify the properties you want to retrieve
                $searcher.PropertiesToLoad.AddRange(@('name', 'grouptype', 'memberof', 'member', 'samaccountname', 'distinguishedname'))

                # Execute the search
                $results = $searcher.FindAll()

                # Loop through the results
                foreach ($result in $results) {
                    $properties = $result.Properties
                    
                    [PSCustomObject]@{
                        GroupName         = $properties['name'] -as [string]
                        GroupType         = $properties['grouptype'] -as [int]
                        MemberOf          = $properties['memberof'] -as [string[]]
                        Members           = $properties['member'] -as [string[]]
                        SamAccountName    = $properties['samaccountname'] -as [string]
                        DistinguishedName = $properties['distinguishedname'] -as [string]
                        Time              = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                        UTCTime           = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                    }
                }
            }
        $groups
    }
}



#----------------------------GROUP MEMBERSHIP-----------------------------------

function Get-DomainGroupMembership {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        [string[]]
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
        $group_members = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                # Define the LDAP query string to find all groups
                $searcher = [adsisearcher]"(objectCategory=group)"

                # Specify the properties you want to retrieve
                $searcher.PropertiesToLoad.AddRange(@('name', 'member', 'distinguishedname'))

                # Execute the search
                $results = $searcher.FindAll()

                # Loop through the results
                $groups = @()
                foreach ($result in $results) {
                    $properties = $result.Properties
                    
                    $groupName = $properties['name'] -as [string]
                    
                    # Skip if GroupName is '0' or empty
                    if ($groupName -eq '0' -or -not $groupName) { continue }
                    
                    $members = @()
                    # If the group has members, resolve their distinguished names to more friendly Common Names (CN)
                    if ($properties['member']) {
                        foreach ($memberDN in $properties['member']) {
                            $memberSearcher = [adsisearcher]"(distinguishedName=$memberDN)"
                            $memberSearcher.PropertiesToLoad.Add('cn')
                            $member = $memberSearcher.FindOne()
                            if ($member) {
                                $members += $member.Properties['cn'] -as [string]
                            }
                        }
                    }
                    
                    $groups += [PSCustomObject]@{
                        GroupName         = $groupName
                        Members           = $members -join ', '
                        DistinguishedName = $properties['distinguishedname'] -as [string]
                        Time              = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                        UTCTime           = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                    }
                }
                $groups
        }
        $group_members = $group_members | Where-Object { $_.GroupName -ne $null }
        $group_members

    }
}


#------------------------------SERVICE ACCOUNTS----------------------------
function Get-ServiceAccount {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        [string[]]
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

        $service_accounts = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                # Define the LDAP query string to find all users with a servicePrincipalName set
                $searcher = [adsisearcher]"(&(objectCategory=user)(servicePrincipalName=*))"

                # Specify the properties you want to retrieve
                $searcher.PropertiesToLoad.AddRange(@('samaccountname', 'serviceprincipalname', 'distinguishedname', 'logoncount', 'description', 
                'badpasswordtime', 'pwdlastset', 'whencreated', 'admincount'))

                # Execute the search
                $results = $searcher.FindAll()

                # Loop through the results
                $service_accounts = @()
                foreach ($result in $results) {
                    $properties = $result.Properties

                    $service_accounts += [PSCustomObject]@{
                        Username               = $properties['samaccountname'] -as [string]
                        ServicePrincipalNames  = ($properties['serviceprincipalname'] -as [string[]]) -join ', '
                        DistinguishedName      = $properties['distinguishedname'] -as [string]
                        LogonCount             = $properties['logoncount'] -as [int]
                        Description            = $properties['description'] -as [string]
                        BadPasswordTime        = [datetime]::FromFileTime($properties['badpasswordtime'][0] -as [long]).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                        PwdLastSet             = [datetime]::FromFileTime($properties['pwdlastset'][0] -as [long]).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                        WhenCreated            = $properties['whencreated'] -as [datetime]
                        AdminCount             = $properties['admincount'] -as [string]
                        Time                   = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                        UTCTime                = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                    }
                }

                $service_accounts
        }

        $service_accounts
    }

}


#------------------------GROUP POLICY-----------------------------------------

function Get-GPOInfo {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        [string[]]
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

        $gpos = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {

                $searcher = [adsisearcher]"(objectClass=groupPolicyContainer)"
                $searcher.PageSize = 1000 # Adjust as needed to handle large result sets
                $results = $searcher.FindAll()

                $gpos = @()

                foreach ($result in $results) {
                    $properties = $result.Properties
                    $gpos += [PSCustomObject]@{
                        Name              = $properties['displayname'][0]
                        Id                = $properties['name'][0] # The unique identifier for the GPO
                        DistinguishedName = $properties['distinguishedname'][0]
                        WhenCreated       = ($properties['whencreated'][0]).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                        WhenChanged       = ($properties['whenchanged'][0]).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                        Time              = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                        UTCTime           = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                    }
                }

                $gpos
            
            }

        $gpos
    }

}




#-----------------------EVENT LOGS-------------------------------------------

function Get-ADEventLog {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        [string[]]
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
        $AD_events = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {

            $eventArray = @(
                [PSCustomObject]@{
                    EventId = 216
                    Description = 'A database location change was detected'
                },
                [PSCustomObject]@{
                    EventId = 325
                    Description = 'The database engine created a new database'
                },
                [PSCustomObject]@{
                    EventId = 326
                    Description = 'The database engine attached a database'
                },
                [PSCustomObject]@{
                    EventId = 327
                    Description = 'The database engine deteached a database'
                }
            )

            $eventIds = @(216, 325, 326, 327)
            $provider = 'ESENT'

            # Using [adsisearcher] to get Domain Controllers
            $searcher = [adsisearcher]'(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
            $domainControllers = $searcher.FindAll() | ForEach-Object { $_.Properties['dnshostname'][0] }

            $results = @()
            foreach ($hostname in $domainControllers) {
                foreach ($id in $eventIds) {
                    try {
                        $events = Get-WinEvent -ComputerName $hostname -FilterHashtable @{
                            LogName       = 'Application'
                            ProviderName  = $provider
                            Id            = $id
                        } -ErrorAction Stop
                        
                        foreach ($event in $events) {
                            $eventDescription = ($eventArray | Where-Object {$_.EventId -eq $event.Id}).Description
                            $results += [PSCustomObject]@{
                                DCName               = $hostname
                                EventID              = $event.Id
                                Description          = $eventDescription
                                TimeCreated          = $event.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                                ProviderName         = $event.ProviderName
                                Message              = $event.Message
                                Time                 = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                                UTCTime              = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffK')
                            }
                        }
                    }
                    catch {
                        #Write-Warning "Failed to query event $id from $hostname. Error: $_"
                    }
                }
            }
            return $results
        }
        $AD_events
    }
}