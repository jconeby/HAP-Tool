param (
    [Parameter(Mandatory=$true)]
    [array]$hostname,

    [Parameter(Mandatory=$true)]
    [string]$username,

    [Parameter(Mandatory=$true)]
    [string]$password,

    [Parameter(Mandatory=$true)]
    [string]$elasticURL,

    [Parameter(Mandatory=$true)]
    [string]$elasticUsername,

    [Parameter(Mandatory=$true)]
    [string]$elasticPassword

)

Import-Module -Name .\functions.psm1

# Create Credential Object for Windows creds
[SecureString]$secureString = $password | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureString

# Create Elasticsearch Credential Object
[SecureString]$elasticSecureString = ConvertTo-SecureString -String $elasticPassword -AsPlainText -Force
[PSCredential]$elasticCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $elasticUsername, $elasticSecureString

# Ignore SSL certificate validation
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Array of categories and data arrays
$categories = @(
    @{
        IndexName = "hap-processes"
        Category = "processes"
        DataArray = (Get-WmiProcess -ComputerName $ComputerName -Credential $Credential)
    },
    @{
        IndexName = "hap-services"
        Category = "services"
        DataArray = (Get-ServiceInfo -ComputerName $ComputerName -Credential $Credential)
    },
    @{
        IndexName = "hap-connections"
        Category = "connections"
        DataArray = (Get-Connection -ComputerName $ComputerName -Credential $Credential)
    },
    @{
        IndexName = "hap-scheduled-tasks"
        Category = "schtasks"
        DataArray = (Get-SchTask -ComputerName $ComputerName -Credential $Credential)
    },
    @{
        IndexName = "hap-prefetch"
        Category = "prefetch"
        DataArray = (Get-Prefetch -ComputerName $ComputerName -Credential $Credential)
    },
    @{
        IndexName = "hap-os"
        Category = "os"
        DataArray = (Get-OSInfo -ComputerName $ComputerName -Credential $Credential)
    },
    @{
        IndexName = "hap-registry"
        Category = "registry"
        DataArray = (Get-RegistryRun -ComputerName $ComputerName -Credential $Credential)
    },
    @{
        IndexName = "hap-startup"
        Category = "startup"
        DataArray = (Get-StartupFolders -ComputerName $ComputerName -Credential $Credential)
    },
    @{
        IndexName = "hap-local-users"
        Category = "localusers"
        DataArray = (Get-LUser -ComputerName $ComputerName -Credential $Credential)
    },
    @{
        IndexName = "hap-local-groups"
        Category = "localgroups"
        DataArray = (Get-LGroup -ComputerName $ComputerName -Credential $Credential)
    },
    @{
        IndexName = "hap-local-group-members"
        Category = "localgroupmembers"
        DataArray = (Get-LGroupMembers -ComputerName $ComputerName -Credential $Credential)
    },
    @{
        IndexName = "hap-shares"
        Category = "shares"
        DataArray = (Get-ShareInfo -ComputerName $ComputerName -Credential $Credential)
    },
    @{
        IndexName = "hap-logon-history"
        Category = "logonhistory"
        DataArray = (Get-LogonHistory -ComputerName $ComputerName -Credential $Credential)
    }
)

# Index data for each category
foreach ($category in $categories) {
    Index-Data -elasticURL $elasticURL -indexName $category.IndexName -category $category.Category -dataArray $category.DataArray
}

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