<?php
ini_set('max_execution_time', 7200); // Set to 7200 seconds (2 hours)

// Function to get event log days
function getEventLogDays($db_path) {
    $db = new SQLite3($db_path);
    $eventLogDays = $db->querySingle("SELECT setting_value FROM app_settings WHERE setting_key = 'eventLogDays'");
    $db->close();

    return ($eventLogDays !== null) ? $eventLogDays : 30; // Default to 30 if not set
}

$db_path = 'C:\xampp\htdocs\hap-tool\settings.db'; // Path where database file is stored
$eventLogDays = getEventLogDays($db_path);

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
        $output = shell_exec("powershell.exe -ExecutionPolicy Bypass -File script_eventlogs.ps1 $hostnameString $username $password $elasticURL $elasticUsername $elasticPassword $eventLogDays");
    } elseif ($scriptType === "activeDirectory") {
        $output = shell_exec("powershell.exe -ExecutionPolicy Bypass -File script_active_directory.ps1 $hostnameString $username $password $elasticURL $elasticUsername $elasticPassword");
    } elseif ($scriptType === "linuxSurvey") {
        $command = escapeshellcmd("python linux_survey.py $hostnameString $username $password $elasticURL $elasticUsername $elasticPassword");
        $output = shell_exec($command);
    } elseif ($scriptType === "linuxLogs") {
        $command = escapeshellcmd("python linux_system_logs.py $hostnameString $username $password $elasticURL $elasticUsername $elasticPassword");
        $output = shell_exec($command);
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
