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
                }
            }
        }
        $processes
    }
} 

# Change creds as needed
$username = 'Administrator'
$password = '8LegsOnTheSpider!'

# Create Credential Object
[SecureString]$secureString = $password | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureString

$Processes = (Get-WmiProcess -ComputerName "localhost" -Credential $creds)[5..15]

# Elasticsearch server URL
$elasticsearchUrl = "http://192.168.159.140:9200"

# Index name
$indexName = "test-index"

# Create the Elasticsearch document endpoint URL
$documentUrl = "$elasticsearchUrl/$indexName/_doc"

$Processes = @{
    "documents" = $Processes
}

# Convert the $Processes to JSON
$jsonData = $Processes | ConvertTo-Json


# Send the JSON data as the request body to create the document
$response = Invoke-RestMethod -Method 'POST' -Uri $documentUrl -Body $jsonData -ContentType 'application/json'

# Display the response
$response
