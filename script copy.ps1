param (
    [Parameter(Mandatory=$true)]
    [string]$hostname,

    [Parameter(Mandatory=$true)]
    [string]$username,

    [Parameter(Mandatory=$true)]
    [string]$password
)

# Your PowerShell function goes here
function Invoke-MyFunction {
    param (
        [Parameter(Mandatory=$true)]
        [string]$hostname,

        [Parameter(Mandatory=$true)]
        [string]$username,

        [Parameter(Mandatory=$true)]
        [string]$password
    )

    # Example: Get-Process
    Invoke-Command -ComputerName $hostname -Credential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, (ConvertTo-SecureString -String $password -AsPlainText -Force)) -ScriptBlock {
        Get-Process
    }
}

# Invoke the function
$test = Invoke-MyFunction -hostname $hostname -username $username -password $password
$test | Export-Csv -Path C:\xampp\htdocs\windows-enumeration\test.csv
