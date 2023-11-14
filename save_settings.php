<?php
session_start(); // Start the session at the beginning of the script

$db_path = 'C:\\xampp\\htdocs\\hap-tool\\settings.db'; 

// Function to update or insert a setting
function upsert_setting($db, $key, $value) {
    $stmt = $db->prepare('INSERT INTO app_settings (setting_key, setting_value) VALUES (:key, :value)
        ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value');
    $stmt->bindValue(':key', $key, SQLITE3_TEXT);
    $stmt->bindValue(':value', $value, SQLITE3_INTEGER);
    $stmt->execute();
}

// Function to update webapp credentials
function update_credentials($db, $username, $password, $elasticURL, $elasticUsername, $elasticPassword) {
    $db->exec('DELETE FROM webapp_credentials');
    $stmt = $db->prepare('INSERT INTO webapp_credentials (username, password, elasticURL, elasticUsername, elasticPassword) VALUES (:username, :password, :elasticURL, :elasticUsername, :elasticPassword)');
    $stmt->bindValue(':username', $username ?: '', SQLITE3_TEXT);
    $stmt->bindValue(':password', $password ?: '', SQLITE3_TEXT);
    $stmt->bindValue(':elasticURL', $elasticURL ?: '', SQLITE3_TEXT);
    $stmt->bindValue(':elasticUsername', $elasticUsername ?: '', SQLITE3_TEXT);
    $stmt->bindValue(':elasticPassword', $elasticPassword ?: '', SQLITE3_TEXT);
    $stmt->execute();
}

// Create (connect to) SQLite database in file
$db = new SQLite3($db_path);

// Set the error mode to throw exceptions
$db->enableExceptions(true);

try {
    // Handle credentials update
    update_credentials(
        $db,
        $_POST['username'],
        $_POST['password'],
        $_POST['elasticURL'],
        $_POST['elasticUsername'],
        $_POST['elasticPassword']
    );

    // Handle app settings update
    upsert_setting($db, 'eventLogDays', $_POST['eventLogDays']);

    // Set a success message in session
    $_SESSION['success_message'] = "Settings updated successfully.";

    // Redirect back to settings.php
    header('Location: settings.php');
    exit;

} catch (Exception $e) {
    // Store error message in session
    $_SESSION['error_message'] = "An error occurred:\n" . $e->getMessage();

    // Redirect back to settings.php
    header('Location: settings.php');
    exit;
}

// Close the database connection
$db->close();
?>
