<?php
ini_set('max_execution_time', 7200); // Set to 7200 seconds (2 hours)

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $hostnames = $_POST["hostname"];

    if (is_array($hostnames)) {
        $hostnameString = implode(",", $hostnames);
    } else {
        $hostnameString = $hostnames;
    }

    $username = $_POST["username"];
    $password = $_POST["password"];
    $elasticURL = $_POST["elasticURL"];
    $elasticUsername = $_POST["elasticUsername"];
    $elasticPassword = $_POST["elasticPassword"];
    $scriptType = $_POST["scriptType"];

    // Execute PowerShell script based on script type
    if ($scriptType === "survey") {
        $output = shell_exec("powershell.exe -ExecutionPolicy Bypass -File script_survey.ps1 $hostnameString $username $password $elasticURL $elasticUsername $elasticPassword");
    } elseif ($scriptType === "eventLogs") {
        $output = shell_exec("powershell.exe -ExecutionPolicy Bypass -File script_eventlogs.ps1 $hostnameString $username $password $elasticURL $elasticUsername $elasticPassword");
    } elseif ($scriptType === "activeDirectory") {
        $output = shell_exec("powershell.exe -ExecutionPolicy Bypass -File script_active_directory.ps1 $hostnameString $username $password $elasticURL $elasticUsername $elasticPassword");
    }

    // Display the output
    // echo "<pre>$output</pre>";
    // Display the output
    // Display the output only if it's not empty or just spaces
    if (trim($output)) {
        echo "<div style='border: 1px solid #e74c3c; background-color: #fdecea; padding: 10px 15px; margin: 10px 0; border-radius: 4px; color: #e74c3c; font-weight: bold;'><pre>$output</pre></div>";
    } 
    
}
?>
