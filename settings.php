<!DOCTYPE html>
<html lang="en">

    <!-- PHP code that queries data from settings.db SQLite database -->
    <?php
    session_start();
    $db_path = 'C:\xampp\htdocs\hap-tool\settings.db'; // Path where database file is stored
    $db = new SQLite3($db_path);

    // Fetch webapp credentials
    $credentials = $db->querySingle("SELECT * FROM webapp_credentials ORDER BY id DESC LIMIT 1", true);
    $eventLogDays = $db->querySingle("SELECT setting_value FROM app_settings WHERE setting_key = 'eventLogDays'", false);

    $db->close();
    ?>

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings</title>
    
    <style>
        body {
            background-color: #000;
            color: #00FF00;
            margin: 0;
            font-family: Arial, sans-serif;
        }

        .navbar {
            background-color: #000;
            border-bottom: 1px solid #00FF00;
        }

        .navbar-brand,
        .navbar-nav .nav-link {
            color: #00FF00;
            transition: color 0.3s ease;
        }

        .navbar-brand:hover,
        .navbar-nav .nav-link:hover {
            color: #FFF;
        }

        .form-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            text-align: center;
            padding: 20px;
        }

        form {
            width: 100%;
            max-width: 600px;
            margin: 20px auto;
            padding: 20px;
            border: 1px solid #00FF00;
            border-radius: 5px;
            background-color: #000;
        }

        .settings-section + .settings-section {
            margin-top: 20px; /* Reduced space between sections */
        }

        h2 {
            color: #00FF00;
            text-align: center;
            margin-bottom: 20px;
        }

        label {
            display: block;
            text-align: left; /* Align labels to the left */
            color: #00FF00;
            margin-bottom: 5px;
        }

        .form-row {
            display: flex;
            flex-direction: column; /* Align inputs and labels in a column */
            margin-bottom: 10px;
        }

        input[type="text"],
        input[type="password"],
        input[type="number"] {
            width: 100%;
            padding: 10px;
            margin-bottom: 10px; /* Space between inputs */
            border: 1px solid #00FF00;
            border-radius: 5px;
            background-color: #000;
            color: #00FF00;
        }

        input[type="submit"] {
            margin-top: 10px; /* Reduced margin above the submit button */
            padding: 10px 20px;
            display: block; /* Make submit block to fill width */
            margin-left: auto; /* Center the button */
            margin-right: auto; /* Center the button */
            border: none;
            border-radius: 5px;
            background-color: #00FF00;
            color: #000;
            font-weight: bold;
            cursor: pointer;
        }

        input[type="submit"]:hover {
            background-color: #009900;
        }

        /* Normal state with light grey color */
        .icon-gear {
            fill: #D3D3D3; /* Light grey color */
            transition: filter 0.3s; /* Smooth transition for the hover effect */
        }

        /* Hover state */
        .icon-gear:hover {
            filter: brightness(0) invert(1); /* Invert colors to white */
        }

    </style>
    <link rel="stylesheet" href="bootstrap-5.3.0-dist/css/bootstrap.min.css">
</head>
<body>

    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="index.html">OPS C2</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="index.html">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="ir_script.php">Enumerate</a>
                    </li>
                </ul>
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <a class="nav-link" href="settings.php">
                            <img class="icon-gear" src="img/gear-solid.svg" alt="Settings" width="25" height="25">
                        </a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>


    
<!-- Settings Form -->
<div class="form-container">
    <form action="save_settings.php" method="post">
        <!-- Credentials Section -->
        <div class="settings-section" id="credentials-section">
            <h2 style="color:whitesmoke">Credentials</h2>
            <div class="form-row">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" value="<?php echo htmlspecialchars($credentials['username'] ?? ''); ?>" required>
            </div>

            <div class="form-row">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" value="<?php echo htmlspecialchars($credentials['password'] ?? ''); ?>" required>
            </div>

            <div class="form-row">
                <label for="elasticURL">Elastic URL:</label>
                <input type="text" id="elasticURL" name="elasticURL" value="<?php echo htmlspecialchars($credentials['elasticURL'] ?? ''); ?>" required>
            </div>

            <div class="form-row">
                <label for="elasticUsername">Elastic Username:</label>
                <input type="text" id="elasticUsername" name="elasticUsername" value="<?php echo htmlspecialchars($credentials['elasticUsername'] ?? ''); ?>" required>
            </div>

            <div class="form-row">
                <label for="elasticPassword">Elastic Password:</label>
                <input type="password" id="elasticPassword" name="elasticPassword" value="<?php echo htmlspecialchars($credentials['elasticPassword'] ?? ''); ?>" required>
            </div>
        </div>

        <!-- App Settings Section -->
        <div class="settings-section" id="app-settings-section">
            <h2 style="color:whitesmoke">App Settings</h2>
            <div class="form-row">
                <label for="eventLogDays">Event Log Days:</label>
                <input type="number" id="eventLogDays" name="eventLogDays" value="<?php echo htmlspecialchars($eventLogDays ?? 0); ?>" required>
            </div>
        </div>

        <input type="submit" value="Save Settings">
    </form>
</div>

<!-- Success message for posting creds to SQLite DB -->
<?php if (!empty($_SESSION['success_message'])): ?>
    <div class="alert alert-success" style="max-width: 600px; margin: 20px auto; text-align: center;">
        <?php 
        echo $_SESSION['success_message'];
        unset($_SESSION['success_message']); // Clear the message so it doesn't appear again
        ?>
    </div>
<?php endif; ?>

<script src="bootstrap-5.3.0-dist/js/bootstrap.min.js"></script>
</body>
</html>
