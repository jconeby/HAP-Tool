<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OPSC2</title>
    <style>
        body {
            background-color: #000;
            color: #00FF00;
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
            height: 100vh;
            text-align: center;
        }

        form {
            max-width: 600px; /* Increased the maximum width */
            width: 100%;
            padding: 20px;
            border: 1px solid #00FF00;
            border-radius: 5px;
            background-color: #000;
            margin-top: 20px;
        }

        label {
            display: block;
            text-align: center; /* Center align the labels */
            color: #00FF00;
            margin-bottom: 3px;
        }

        .form-row {
            display: flex;
            flex-wrap: wrap; /* Added flex-wrap property to wrap elements to the next line */
            margin-bottom: 15px; /* Adjusted margin-bottom to reduce spacing */
            align-items: center; /* Added to vertically align label and input */
        }

        .form-row label,
        .form-row input {
            flex: 1;
            margin-right: 10px; /* Added margin-right for spacing */
            text-align: center; /* Center align the inputs */
        }

        h1 {
            font-family: 'Courier New', monospace;
            font-weight: bold;
            color: #00FF00;
            text-align: center;
            margin-top: 0;
            margin-bottom: 20px;
            letter-spacing: 2px; 
            }

        select {
            max-width: 300px; /* Increased the maximum width */
            width: 100%;
            padding: 20px;
            border: 1px solid #00FF00;
            border-radius: 5px;
            background-color: #000;
            margin-top: 20px;
            color: #00FF00;
        }

        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #00FF00;
            border-radius: 5px;
            background-color: #000;
            color: #00FF00;
        }

        input[type="submit"] {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            background-color: #00FF00;
            color: #000;
            font-weight: bold;
            cursor: pointer;
            width: 200px;
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

<!-- PHP code to query data from settings.db SQLite database -->
<?php
$db_path = 'C:\xampp\htdocs\hap-tool\settings.db'; // Adjust the path accordingly
$db = new SQLite3($db_path);

// Fetch webapp credentials
$credentials = $db->querySingle("SELECT * FROM webapp_credentials ORDER BY id DESC LIMIT 1", true);

$db->close();
?>

<!-- Form Content -->
<div class="form-container">
    <h1>IR Script</h1>
    <form action="execute.php" method="post">
        <div class="form-row">
            <label for="hostname">Hostnames:</label>
            <input type="text" id="hostname" name="hostname[]" value="" required multiple="multiple">
        </div>        
        
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

        <div class="form-row">
            <label for="scriptType">Script Type:</label>
            <select id="scriptType" name="scriptType" required>
                <option value="survey">Windows Survey</option>
                <option value="eventLogs">Windows Event Logs</option>
                <option value="activeDirectory">Active Directory</option>
                <option value="linuxSurvey">Linux Survey</option>
                <option value="linuxLogs">Linux System Logs</option>
            </select>
        </div>
        
        <input type="submit" value="Run Script" onclick="runScript(event)">
    </form>
</div>

<script src="bootstrap-5.3.0-dist/js/bootstrap.min.js"></script>
<script>
    function runScript(event) {
        var spinner = document.createElement("div");
        spinner.className = "spinner-border text-light";
        spinner.style.marginTop = "20px";
        document.querySelector(".form-container").appendChild(spinner);

        var submitButton = document.querySelector("input[type='submit']");
        submitButton.disabled = true;
        document.body.style.cursor = "wait";

        // Send an asynchronous request to execute.php
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "execute.php", true);
        xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");

        xhr.onreadystatechange = function() {
            if (xhr.readyState === XMLHttpRequest.DONE) {
                if (xhr.status === 200) {
                    var response = xhr.responseText;
                    var outputContainer = document.createElement("div");
                    outputContainer.innerHTML = "<pre>" + response + "</pre>";
                    document.querySelector(".form-container").appendChild(outputContainer);

                    var messageBox = document.createElement("div");
                    messageBox.className = "alert alert-success";
                    messageBox.textContent = "Incident response script completed!";
                    document.querySelector(".form-container").appendChild(messageBox);

                    submitButton.disabled = false;
                    document.body.style.cursor = "default";
                } else {
                    var messageBox = document.createElement("div");
                    messageBox.className = "alert alert-danger";
                    messageBox.textContent = "An error occurred while executing the script.";
                    document.querySelector(".form-container").appendChild(messageBox);

                    submitButton.disabled = false;
                    document.body.style.cursor = "default";
                }

                document.querySelector(".spinner-border").remove();
            }
        };

        var hostname = document.getElementById("hostname").value.split(",").map(function(item) {
            return item.trim();  // trim whitespace from each hostname
        });
        var username = document.getElementById("username").value;
        var password = document.getElementById("password").value;
        var elasticURL = document.getElementById("elasticURL").value;
        var elasticUsername = document.getElementById("elasticUsername").value;
        var elasticPassword = document.getElementById("elasticPassword").value;
        var scriptType = document.getElementById("scriptType").value;

        var params = "hostname=" + encodeURIComponent(hostname) + "&username=" + encodeURIComponent(username) + "&password=" 
        + encodeURIComponent(password) + "&elasticURL=" + encodeURIComponent(elasticURL) + "&elasticUsername=" + encodeURIComponent(elasticUsername) + 
        "&elasticPassword=" + encodeURIComponent(elasticPassword) + "&scriptType=" + encodeURIComponent(scriptType);
        xhr.send(params);

        event.preventDefault(); // Prevent the default form submission
    }
</script>
</body>
</html>
