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

# Array of categories and data arrays
$categories = @(
    @{
        IndexName = "hap-processes"
        Category = "processes"
        DataArray = (Get-WmiProcess -ComputerName $hostnames -Credential $Credential)
    },
    @{
        IndexName = "hap-services"
        Category = "services"
        DataArray = (Get-ServiceInfo -ComputerName $hostnames -Credential $Credential)
    },
    @{
        IndexName = "hap-connections"
        Category = "connections"
        DataArray = (Get-Connection -ComputerName $hostnames -Credential $Credential)
    },
    @{
        IndexName = "hap-scheduled-tasks"
        Category = "schtasks"
        DataArray = (Get-SchTask -ComputerName $hostnames -Credential $Credential)
    },
    @{
        IndexName = "hap-prefetch"
        Category = "prefetch"
        DataArray = (Get-Prefetch -ComputerName $hostnames -Credential $Credential)
    },
    @{
        IndexName = "hap-os"
        Category = "os"
        DataArray = (Get-OSInfo -ComputerName $hostnames -Credential $Credential)
    },
    @{
        IndexName = "hap-registry"
        Category = "registry"
        DataArray = (Get-RegistryRun -ComputerName $hostnames -Credential $Credential)
    },
    @{
        IndexName = "hap-startup"
        Category = "startup"
        DataArray = (Get-StartupFolders -ComputerName $hostnames -Credential $Credential)
    },
    @{
        IndexName = "hap-local-users"
        Category = "localusers"
        DataArray = (Get-LUser -ComputerName $hostnames -Credential $Credential)
    },
    @{
        IndexName = "hap-local-groups"
        Category = "localgroups"
        DataArray = (Get-LGroup -ComputerName $hostnames -Credential $Credential)
    },
    @{
        IndexName = "hap-local-group-members"
        Category = "localgroupmembers"
        DataArray = (Get-LGroupMembers -ComputerName $hostnames -Credential $Credential)
    },
    @{
        IndexName = "hap-shares"
        Category = "shares"
        DataArray = (Get-ShareInfo -ComputerName $hostnames -Credential $Credential)
    },
    @{
        IndexName = "hap-logon-history"
        Category = "logonhistory"
        DataArray = (Get-LogonHistory -ComputerName $hostnames -Credential $Credential)
    }
)


# Index data for each category
foreach ($category in $categories) {
    Index-Data -elasticURL $elasticURL -Credential $elasticCredentials -indexName $category.IndexName -dataArray $category.DataArray;
    Create-IndexPattern -elasticURL $elasticURL -Credential $elasticCredentials -indexPattern $category.IndexName
}

# Create default index pattern
Create-IndexPattern -elasticURL $elasticURL -Credential $elasticCredentials -indexPattern 'hap-*'

