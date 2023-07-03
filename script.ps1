param (
    [Parameter(Mandatory=$true)]
    [string]$hostname,

    [Parameter(Mandatory=$true)]
    [string]$username,

    [Parameter(Mandatory=$true)]
    [string]$password,

    [Parameter(Mandatory=$true)]
    [string]$elasticURL

)

Import-Module -Name .\functions.psm1

# Create Credential Object for Windows creds
[SecureString]$secureString = $password | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureString

# Ignore SSL certificate validation
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# PROCESSES
$indexName = "hap-processes"
$category = "processes"
$processes = (Get-WmiProcess -ComputerName $hostname -Credential $creds)
Index-Data -elasticURL $elasticURL -indexName $indexName -category $category -dataArray $processes

# SERVICES
$indexName = "hap-services"
$category = "services"
$services = (Get-ServiceInfo -ComputerName $hostname -Credential $creds)
Index-Data -elasticURL $elasticURL -indexName $indexName -category $category -dataArray $services

# CONNECTIONS
$indexName = "hap-connections"
$category = "connections"
$connections = (Get-Connection -ComputerName $hostname -Credential $creds)
Index-Data -elasticURL $elasticURL -indexName $indexName -category $category -dataArray $connections

# SCHEDULED TASKS
$indexName = "hap-scheduled-tasks"
$category = "schtasks"
$scheduled_tasks = (Get-SchTask -ComputerName $hostname -Credential $creds)
Index-Data -elasticURL $elasticURL -indexName $indexName -category $category -dataArray $scheduled_tasks

# PREFETCH
$indexName = "hap-prefetch"
$category = "prefetch"
$prefetch = (Get-Prefetch -ComputerName $hostname -Credential $creds)
Index-Data -elasticURL $elasticURL -indexName $indexName -category $category -dataArray $prefetch

# OS INFO
$indexName = "hap-os"
$category = "os"
$os_info = (Get-OSInfo -ComputerName $hostname -Credential $creds)
Index-Data -elasticURL $elasticURL -indexName $indexName -category $category -dataArray $os_info

# REGISTRY
$indexName = "hap-registry"
$category = "registry"
$registry = (Get-RegistryRun -ComputerName $hostname -Credential $creds)
Index-Data -elasticURL $elasticURL -indexName $indexName -category $category -dataArray $registry

# STARTUP FOLDERS
$indexName = "hap-startup"
$category = "startup"
$startups = (Get-StartupFolders -ComputerName $hostname -Credential $creds)
Index-Data -elasticURL $elasticURL -indexName $indexName -category $category -dataArray $startups

# LOCAL USERS
$indexName = "hap-local-users"
$category = "localusers"
$local_users = (Get-LUser -ComputerName $hostname -Credential $creds)
Index-Data -elasticURL $elasticURL -indexName $indexName -category $category -dataArray $local_users

# LOCAL GROUPS
$indexName = "hap-local-groups"
$category = "localgroups"
$local_groups = (Get-LGroup -ComputerName $hostname -Credential $creds)
Index-Data -elasticURL $elasticURL -indexName $indexName -category $category -dataArray $local_groups

# LOCAL GROUP MEMBERS
$indexName = "hap-local-group-members"
$category = "localgroupmembers"
$local_group_members = (Get-LGroupMembers -ComputerName $hostname -Credential $creds)
Index-Data -elasticURL $elasticURL -indexName $indexName -category $category -dataArray $local_group_members

# SHARES
$indexName = "hap-shares"
$category = "shares"
$shares = (Get-ShareInfo -ComputerName $hostname -Credential $creds)
Index-Data -elasticURL $elasticURL -indexName $indexName -category $category -dataArray $shares

# LOGON HISTORY
$indexName = "hap-logon-history"
$category = "logonhistory"
$logon_history = (Get-LogonHistory -ComputerName $hostname -Credential $creds)
Index-Data -elasticURL $elasticURL -indexName $indexName -category $category -dataArray $logon_history

# EVENT LOGS
$indexName = "hap-eventlogs"
$documentUrl = "$elasticURL/$indexName/_doc"

# Capture the last 30 days of events
$BeginTime = (Get-Date).AddDays(-30)
$EndTime = (Get-Date)

# Path where the files are stored on the web server
$local_path = ($env:USERPROFILE + '\AppData\Local\Temp\XML\')

Get-CriticalEventXML -BeginTime $BeginTime -EndTime $EndTime -ComputerName $hostname -Credential $creds

$xmlFiles = Get-ChildItem -Path $local_path -Filter "*-events.xml"

        foreach ($file in $xmlFiles) {
            $xmlData = Import-Clixml -Path $file.FullName
            $enriched = $xmlData | Enrich-Event

            foreach ($event in $enriched) {
                $eventObj = @{
                    "event" = $event
                }
                $jsonData = $eventObj | ConvertTo-Json
                # Send the JSON data as the request body to create the document
                Invoke-RestMethod -Method 'POST' -Uri $documentUrl -Body $jsonData -ContentType 'application/json'
            }
        }