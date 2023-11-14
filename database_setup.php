<?php

$db_path = 'C:\xampp\htdocs\hap-tool\settings.db'; // Path where database file is stored

// Create (connect to) SQLite database in file
$db = new SQLite3($db_path);

// Set the error mode to throw exceptions
$db->enableExceptions(true);

// Create tables to store credentials and settings
$queries = [
    "CREATE TABLE IF NOT EXISTS webapp_credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        elasticURL TEXT NOT NULL,
        elasticUsername TEXT NOT NULL,
        elasticPassword TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS app_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        setting_key TEXT UNIQUE NOT NULL,
        setting_value INTEGER NOT NULL
    )"
];

try {
    foreach ($queries as $query) {
        $db->exec($query);
    }
    echo "Database and tables created successfully.";
} catch (Exception $e) {
    echo "An error occurred:\n" . $e->getMessage();
}

// Close the database connection
$db->close();
?>
