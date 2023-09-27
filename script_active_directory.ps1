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

Import-Module -Name .\functions.psm1 -WarningAction Silent > $null

# Create Credential Object for Windows creds
[SecureString]$secureString = $password | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$Credential = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureString

# Create Elasticsearch Credential Object
[SecureString]$elasticSecureString = ConvertTo-SecureString -String $elasticPassword -AsPlainText -Force 
[PSCredential]$elasticCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $elasticUsername, $elasticSecureString

# Ignore SSL certificate validation
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# hostname array
$hostnames = Split-StringWithComma -InputString $hostnameString[0]

# Array of hosts that accept WinRM requests
$successfulHosts = @()

foreach ($hostname in $hostnames) {
    try {
        # Attempting to connect and execute a simple command
        Invoke-Command -ComputerName $hostname -Credential $Credential -ScriptBlock {
        } -ErrorAction Stop
        $successfulHosts += $hostname
    } catch {
        Write-Host "Error connecting to $hostname"
    }
}

# Array of categories and data arrays
$categories = @(
    @{
        IndexName = "hap-ad-dc"
        Category = "domain-controllers"
        DataArray = (Get-DomainController -ComputerName $successfulHosts -Credential $Credential)
    },
    @{
        IndexName = "hap-ad-protected-users"
        Category = "protected-users"
        DataArray = (Get-ProtectedUsers -ComputerName $successfulHosts -Credential $Credential)
    },
    @{
        IndexName = "hap-ad-users"
        Category = "domain-users"
        DataArray = (Get-DomainUser -ComputerName $successfulHosts -Credential $Credential)
    },
    @{
        IndexName = "hap-ad-groups"
        Category = "domain-groups"
        DataArray = (Get-DomainGroup -ComputerName $successfulHosts -Credential $Credential)
    },
    @{
        IndexName = "hap-ad-group-membership"
        Category = "domain-group-membership"
        DataArray = (Get-DomainGroupMembership -ComputerName $successfulHosts -Credential $Credential)
    },
    @{
        IndexName = "hap-ad-service-accounts"
        Category = "domain-service-accounts"
        DataArray = (Get-ServiceAccount -ComputerName $successfulHosts -Credential $Credential)
    },
    @{
        IndexName = "hap-ad-gpo"
        Category = "domain-group-policy"
        DataArray = (Get-GPOInfo -ComputerName $successfulHosts -Credential $Credential)
    },
    @{
        IndexName = "hap-ad-eventlog"
        Category = "domain-event-logs"
        DataArray = (Get-ADEventLog -ComputerName $successfulHosts -Credential $Credential)
    }
    
)

# Index data for each category
foreach ($category in $categories) {
    Index-Data -elasticURL $elasticURL -Credential $elasticCredentials -indexName $category.IndexName -dataArray $category.DataArray > $null;
    Create-IndexPattern -elasticURL $elasticURL -Credential $elasticCredentials -indexPattern $category.IndexName > $null
}

# Log that the script was ran on the crew_log index
$logObject = [PSCustomObject]@{
    "timestamp" = (Get-Date).ToUniversalTime().ToString("o")
    "hostname"  = $env:COMPUTERNAME
    "command"   = ("panacea tool AD script ran on " + $hostnameString)
}

$logJson = $logObject | ConvertTo-Json
$documentUrl = "$elasticUrl/crew_log/_doc"
Invoke-RestMethod -Method 'POST' -Uri $documentUrl -Body $logJson -ContentType 'application/json' -Credential $elasticCredentials > $null