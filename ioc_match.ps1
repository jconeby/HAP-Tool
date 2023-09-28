$interesting_files = @()

# Array of bad files
$bad_files = @('backup.bat', 'cl64.exe', 'update.bat', 'Win.exe', 'billagent.exe', 'nc.exe',
        'update.exe', 'WmiPrvSE.exe', 'billaudit.exe', 'rar.exe', 'vm3dservice.exe', 'WmiPreSV.exe',
        'cisco_up.exe', 'SMSvcService.exe', 'watchdogd.exe')

# File paths of where to look for bad files
$file_paths = @('C:\Users\Public\Appfile', 'C:\Perflogs', 'C:\Windows\Temp')

# Loop through each directory looking if it contains any bad files
$matches = foreach ($path in $file_paths) {
    try {
        Get-ChildItem -Path $path -Include $bad_files -File -Recurse -Force -ErrorAction SilentlyContinue
    }
    catch {
        # Silently continue on error
    }
}

# Find possible malicious filenames
$regex_match = Get-ChildItem -Path "C:\Windows" -Filter "*.exe" -File -ErrorAction SilentlyContinue | 
               Where-Object { $_.Name -match "^[a-zA-Z]{8}\.exe$" }

# Combine results
if($matches -ne $null) { $interesting_files += $matches }
if($regex_match -ne $null) { $interesting_files += $regex_match }

# Output or further process $interesting_files as needed
$interesting_files | ForEach-Object { Write-Output $_.FullName }