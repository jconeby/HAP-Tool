param (
    [Parameter(Mandatory=$true)]
    [array]$hostnameString,

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
[PSCredential]$Credential = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureString

# Create Elasticsearch Credential Object
[SecureString]$elasticSecureString = ConvertTo-SecureString -String $elasticPassword -AsPlainText -Force
[PSCredential]$elasticCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $elasticUsername, $elasticSecureString

# Ignore SSL certificate validation
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Convert value passed by php to an array in PowerShell
$hostnames = Split-StringWithComma -InputString $hostnameString[0]

# EVENT LOGS
$indexName = "hap-eventlogs"
$documentUrl = "$elasticURL/$indexName/_doc"

# Capture the last 1 days of events
$BeginTime = (Get-Date).AddDays(-1)
$EndTime = (Get-Date)

# Path where the files are stored on the web server
$local_path = ($env:USERPROFILE + '\AppData\Local\Temp\XML\')

Get-CriticalEventXML -BeginTime $BeginTime -EndTime $EndTime -ComputerName $hostnames -Credential $Credential

$xmlFiles = Get-ChildItem -Path $local_path -Filter "*-events.xml"

        foreach ($file in $xmlFiles) {
            $xmlData = Import-Clixml -Path $file.FullName
            $enriched = $xmlData | Enrich-Event

            foreach ($event in $enriched) {
                $eventObj = @{
                    "hap" = $event
                }
                $jsonData = $eventObj | ConvertTo-Json
                # Send the JSON data as the request body to create the document
                Invoke-RestMethod -Method 'POST' -Uri $documentUrl -Body $jsonData -ContentType 'application/json' -Credential $elasticCredentials

            } #End of inner loop
        } #End of outer loop


# CREATE INDEX PATTERN FOR EVENT LOGS
Create-IndexPattern -elasticURL $elasticURL -Credential $elasticCredentials -indexPattern 'hap-eventlogs*'
