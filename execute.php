<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $hostname = $_POST["hostname"];
    $username = $_POST["username"];
    $password = $_POST["password"];

    // Execute PowerShell script
    $output = shell_exec("powershell.exe -ExecutionPolicy Bypass -File script.ps1 $hostname $username $password");
    
    // Display the output
    echo "<pre>$output</pre>";
}
?>
