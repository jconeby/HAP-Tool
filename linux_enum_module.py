from datetime import datetime
import paramiko
from elasticsearch import Elasticsearch, helpers, exceptions as es_exceptions

# LOCAL USERS
def get_users_and_insert(hostname, username, password, es_url, es_user, es_pass, es_index):
    # Establishing Elasticsearch Connection
    es = Elasticsearch(
        [es_url],
        basic_auth=(es_user, es_pass),
        verify_certs=False,
    )
    
    # List to hold the user information.
    users_info = []
    try:
        # SSH Client setup and connect.
        with paramiko.SSHClient() as client:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname, username=username, password=password)
            
            # Execute command and process output.
            stdin, stdout, stderr = client.exec_command('cat /etc/passwd')
            for line in stdout.read().decode('utf-8').splitlines():
                user = line.split(":")[0]
                users_info.append({"user": user, "userinfo": line})  # Added userinfo
                
    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")

    # Get the current UTC time in ISO 8601 format
    timestamp = datetime.utcnow().isoformat()

    # Prepare Elasticsearch actions and perform bulk insert.
    actions = [
        {
            "_index": es_index, 
            "_source": {
                "hostname": hostname, 
                "user": user_info["user"], 
                "userinfo": user_info["userinfo"],  # Added userinfo
                "timestamp": timestamp  
            }
        } 
        for user_info in users_info  # Modified to accommodate userinfo
    ]
    
    try:
        helpers.bulk(es, actions)
    except es_exceptions.ElasticsearchException as e:
        print(f"Error occurred while inserting data into Elasticsearch: {str(e)}")

# LOCAL GROUPS

def get_groups_and_insert(hostname, username, password, es_url, es_user, es_pass, es_index):
    # Establishing Elasticsearch Connection
    es = Elasticsearch(
        [es_url],
        basic_auth=(es_user, es_pass),
        verify_certs=False,
    )
    
    # List to hold the group information.
    groups_info = []
    try:
        # SSH Client setup and connect.
        with paramiko.SSHClient() as client:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname, username=username, password=password)
            
            # Execute command and process output.
            stdin, stdout, stderr = client.exec_command('cat /etc/group')
            for line in stdout.read().decode('utf-8').splitlines():
                group = line.split(":")[0]  # Extracting group name
                groups_info.append({"group": group, "groupinfo": line})  # Added groupinfo
                
    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")

    # Get the current UTC time in ISO 8601 format
    timestamp = datetime.utcnow().isoformat()

    # Prepare Elasticsearch actions and perform bulk insert.
    actions = [
        {
            "_index": es_index, 
            "_source": {
                "hostname": hostname, 
                "group": group_info["group"],  # Use group from group_info
                "groupinfo": group_info["groupinfo"],  # Added groupinfo
                "timestamp": timestamp  
            }
        } 
        for group_info in groups_info  # Modified to accommodate groupinfo
    ]
    
    try:
        helpers.bulk(es, actions)
    except es_exceptions.ElasticsearchException as e:
        print(f"Error occurred while inserting data into Elasticsearch: {str(e)}")

# PROCESSES

def get_processes_and_insert(hostname, username, password, es_url, es_user, es_pass, es_index):
    # Establishing Elasticsearch Connection
    es = Elasticsearch(
        [es_url],
        basic_auth=(es_user, es_pass),
        verify_certs=False,
    )

    # List to hold the process information.
    processes_info = []
    try:
        # SSH Client setup and connect.
        with paramiko.SSHClient() as client:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname, username=username, password=password)
            
            # Execute command and process output.
            stdin, stdout, stderr = client.exec_command('ps -auxww')
            # Skipping the header line of the output
            lines = stdout.read().decode('utf-8').splitlines()[1:]
            for line in lines:
                # Splitting by whitespace to extract fields
                fields = line.split(None, 10)
                processes_info.append({
                    "USER": fields[0],
                    "PID": fields[1],
                    "%CPU": fields[2],
                    "%MEM": fields[3],
                    "VSZ": fields[4],
                    "RSS": fields[5],
                    "TTY": fields[6],
                    "STAT": fields[7],
                    "START": fields[8],
                    "TIME": fields[9],
                    "COMMAND": fields[10]
                })
                
    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")

    # Get the current UTC time in ISO 8601 format
    timestamp = datetime.utcnow().isoformat()

    # Prepare Elasticsearch actions and perform bulk insert.
    actions = [
        {
            "_index": es_index, 
            "_source": {
                "hostname": hostname, 
                "process_info": process_info,  # Added process_info
                "timestamp": timestamp  
            }
        } 
        for process_info in processes_info
    ]
    
    try:
        helpers.bulk(es, actions)
    except es_exceptions.ElasticsearchException as e:
        print(f"Error occurred while inserting data into Elasticsearch: {str(e)}")


# /etc/shadow CONTENTS

def get_shadow_and_insert(hostname, username, password, es_url, es_user, es_pass, es_index):
    # Establishing Elasticsearch Connection
    es = Elasticsearch(
        [es_url],
        basic_auth=(es_user, es_pass),
        verify_certs=False,
    )
    
    # List to hold the shadow information.
    shadow_info_list = []
    try:
        # SSH Client setup and connect.
        with paramiko.SSHClient() as client:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname, username=username, password=password)
            
            # Execute command and process output.
            command = 'sudo -S cat /etc/shadow'  # -S option makes sudo read password from stdin
            stdin, stdout, stderr = client.exec_command(command)
            stdin.write(password + '\n')  # Sending the sudo password
            stdin.flush()

            for line in stdout.read().decode('utf-8').splitlines():
                user, shadow_info = line.split(":", 1)  # Splitting by the first colon
                shadow_info_list.append({"user": user, "shadow_info": line})
                
    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")

    # Get the current UTC time in ISO 8601 format
    timestamp = datetime.utcnow().isoformat()

    # Prepare Elasticsearch actions and perform bulk insert.
    actions = [
        {
            "_index": es_index, 
            "_source": {
                "hostname": hostname, 
                "user": shadow_info["user"], 
                "shadow_info": shadow_info["shadow_info"],
                "timestamp": timestamp  
            }
        } 
        for shadow_info in shadow_info_list
    ]
    
    try:
        helpers.bulk(es, actions)
    except es_exceptions.ElasticsearchException as e:
        print(f"Error occurred while inserting data into Elasticsearch: {str(e)}")

# Lastlog info -- see the users that have logged in recently

def get_lastlog_and_insert(hostname, username, password, es_url, es_user, es_pass, es_index):
    # Establishing Elasticsearch Connection
    es = Elasticsearch(
        [es_url],
        basic_auth=(es_user, es_pass),
        verify_certs=False,
    )

    # List to hold the lastlog information.
    lastlog_info = []
    try:
        # SSH Client setup and connect.
        with paramiko.SSHClient() as client:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname, username=username, password=password)
            
            # Execute command and process output.
            stdin, stdout, stderr = client.exec_command('lastlog')
            # Skipping the header line of the output
            lines = stdout.read().decode('utf-8').splitlines()[1:]
            for line in lines:
                fields = line.split(None, 3)  # Splitting by whitespace to extract fields
                # Checking if the length of fields is 4 which indicates the user has logged in before
                if len(fields) == 4:
                    username, port, from_, latest = fields
                else:  # This user has never logged in, so 'Latest' field is 'Never'
                    username = fields[0]
                    port = from_ = ""
                    latest = "Never"

                lastlog_info.append({
                    "Username": username,
                    "Port": port,
                    "From": from_,
                    "Latest": latest
                })
                
    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")

    # Get the current UTC time in ISO 8601 format
    timestamp = datetime.utcnow().isoformat()

    # Prepare Elasticsearch actions and perform bulk insert.
    actions = [
        {
            "_index": es_index, 
            "_source": {
                "hostname": hostname, 
                "lastlog_info": lastlog,  # Added lastlog_info
                "timestamp": timestamp  
            }
        } 
        for lastlog in lastlog_info
    ]
    
    try:
        helpers.bulk(es, actions)
    except es_exceptions.ElasticsearchException as e:
        print(f"Error occurred while inserting data into Elasticsearch: {str(e)}")

# This function is to identify any odd SSH & Telent logins

def get_auth_logs_and_insert(hostname, username, password, es_url, es_user, es_pass, es_index):
    # Establishing Elasticsearch Connection
    es = Elasticsearch(
        [es_url],
        basic_auth=(es_user, es_pass),
        verify_certs=False,
    )
    
    # List to hold the log information.
    logs_info = []
    try:
        # SSH Client setup and connect.
        with paramiko.SSHClient() as client:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname, username=username, password=password)
            
            # Execute command and process output.
            command = "grep -E 'ssh|telnet' /var/log/auth.log"
            stdin, stdout, stderr = client.exec_command(command)
            for line in stdout.read().decode('utf-8').splitlines():
                logs_info.append({"loginfo": line})  # Added loginfo
                
    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")

    # Get the current UTC time in ISO 8601 format
    timestamp = datetime.utcnow().isoformat()

    # Prepare Elasticsearch actions and perform bulk insert.
    actions = [
        {
            "_index": es_index, 
            "_source": {
                "hostname": hostname, 
                "loginfo": log_info["loginfo"],  # Added loginfo
                "timestamp": timestamp  
            }
        } 
        for log_info in logs_info  # Modified to accommodate loginfo
    ]
    
    try:
        helpers.bulk(es, actions)
    except es_exceptions.ElasticsearchException as e:
        print(f"Error occurred while inserting data into Elasticsearch: {str(e)}")

# BASH HISTORY

def get_user_history_and_insert(hostname, username, password, es_url, es_user, es_pass, es_index):
    # Establishing Elasticsearch Connection
    es = Elasticsearch(
        [es_url],
        http_auth=(es_user, es_pass),
        verify_certs=False,
    )
    
    # List to hold the history information.
    history_info = []
    
    # Bash command to retrieve history for every user
    command = """
    for user_home in /home/*; do
      user=$(basename "$user_home")
      sudo -S cat "$user_home/.bash_history" 2>/dev/null | while read -r cmd; do
        echo "User: $user, Command: $cmd"
      done
    done
    """
    
    try:
        # SSH Client setup and connect.
        with paramiko.SSHClient() as client:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname, username=username, password=password)
            
            # Execute command and process output.
            stdin, stdout, stderr = client.exec_command(command)
            stdin.write(password + '\n')  # Sending the sudo password
            stdin.flush()

            for line in stdout.read().decode('utf-8').splitlines():
                # Extracting user and command from the line
                user, cmd = line.replace('User: ', '').split(', Command: ', 1)
                history_info.append({"user": user.strip(), "command": cmd.strip(), "history_info": line.strip()})
                
    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")

    # Get the current UTC time in ISO 8601 format
    timestamp = datetime.utcnow().isoformat()

    # Prepare Elasticsearch actions and perform bulk insert.
    actions = [
        {
            "_index": es_index,
            "_source": {
                "hostname": hostname,
                "user": info["user"],
                "command": info["command"],
                "history_info": info["history_info"],
                "timestamp": timestamp
            }
        }
        for info in history_info
    ]

    try:
        helpers.bulk(es, actions)
    except es_exceptions.ElasticsearchException as e:
        print(f"Error occurred while inserting data into Elasticsearch: {str(e)}")


# SERVICES

def get_services_and_insert(hostname, username, password, es_url, es_user, es_pass, es_index):
    # Establishing Elasticsearch Connection
    es = Elasticsearch(
        [es_url],
        basic_auth=(es_user, es_pass),
        verify_certs=False,
    )
    
    # List to hold the service information.
    services_info = []
    try:
        # SSH Client setup and connect.
        with paramiko.SSHClient() as client:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname, username=username, password=password)
            
            # Execute command and process output.
            stdin, stdout, stderr = client.exec_command('service --status-all')
            for line in stdout.read().decode('utf-8').splitlines():
                # Parsing service status and name
                status_symbol = line[4]  # Extracts the '+' or '-' character from the line
                status = "running" if status_symbol == '+' else "stopped"
                service = line[8:].strip()  # Extracts the service name from the line
                services_info.append({"service": service, "status": status, "serviceinfo": line.strip()})
                
    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")

    # Get the current UTC time in ISO 8601 format
    timestamp = datetime.utcnow().isoformat()

    # Prepare Elasticsearch actions and perform bulk insert.
    actions = [
        {
            "_index": es_index,
            "_source": {
                "hostname": hostname,
                "service": service_info["service"],
                "status": service_info["status"],
                "serviceinfo": service_info["serviceinfo"],
                "timestamp": timestamp
            }
        }
        for service_info in services_info
    ]
    
    try:
        helpers.bulk(es, actions)
    except es_exceptions.ElasticsearchException as e:
        print(f"Error occurred while inserting data into Elasticsearch: {str(e)}")


# CRONJOBS

def get_cron_jobs_and_insert(hostname, username, password, es_url, es_user, es_pass, es_index):
    # Establishing Elasticsearch Connection
    es = Elasticsearch(
        [es_url],
        basic_auth=(es_user, es_pass),
        verify_certs=False,
    )

    # List to hold the cron job information.
    cron_jobs_info = []
    try:
        # SSH Client setup and connect.
        with paramiko.SSHClient() as client:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname, username=username, password=password)
            
            # Execute command and process output.
            stdin, stdout, stderr = client.exec_command('cat /etc/crontab')
            for line in stdout.read().decode('utf-8').splitlines():
                if line and not line.startswith("#"):  # Skip comments and empty lines
                    fields = line.split()
                    if len(fields) >= 7:  # Ensure there are enough fields before accessing them
                        cron_job = {
                            "m": fields[0],
                            "h": fields[1],
                            "dom": fields[2],
                            "mon": fields[3],
                            "dow": fields[4],
                            "user": fields[5],
                            "command": ' '.join(fields[6:]),
                            "croninfo": line  # Added croninfo
                        }
                        cron_jobs_info.append(cron_job)

    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")

    # Get the current UTC time in ISO 8601 format
    timestamp = datetime.utcnow().isoformat()

    # Prepare Elasticsearch actions and perform bulk insert.
    actions = [
        {
            "_index": es_index, 
            "_source": {
                "hostname": hostname, 
                **cron_job,
                "timestamp": timestamp  
            }
        } 
        for cron_job in cron_jobs_info  # Modified to accommodate croninfo
    ]

    try:
        helpers.bulk(es, actions)
    except es_exceptions.ElasticsearchException as e:
        print(f"Error occurred while inserting data into Elasticsearch: {str(e)}")


# Get /etc/hosts file

def get_hosts_and_insert(hostname, username, password, es_url, es_user, es_pass, es_index):
    # Establishing Elasticsearch Connection
    es = Elasticsearch(
        [es_url],
        http_auth=(es_user, es_pass),
        verify_certs=False,
    )

    # List to hold the hosts information.
    hosts_info = []
    try:
        # SSH Client setup and connect.
        with paramiko.SSHClient() as client:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname, username=username, password=password)

            # Execute command and process output.
            stdin, stdout, stderr = client.exec_command('cat /etc/hosts')
            for line in stdout.read().decode('utf-8').splitlines():
                if line.strip() and not line.strip().startswith("#"):  # Skip comments and empty lines
                    parts = line.split()
                    if len(parts) >= 2:  # Checking if line has both IP and hostname
                        ip_address = parts[0]
                        for host in parts[1:]:
                            if not host.startswith("#"):  # Skip inline comments
                                hosts_info.append({"ip_address": ip_address, "host": host})  # Structured host_info

    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")

    # Get the current UTC time in ISO 8601 format
    timestamp = datetime.utcnow().isoformat()

    # Prepare Elasticsearch actions and perform bulk insert.
    actions = [
        {
            "_index": es_index,
            "_source": {
                "hostname": hostname,
                **host_info,
                "timestamp": timestamp
            }
        }
        for host_info in hosts_info  # Modified to accommodate structured host_info
    ]

    try:
        helpers.bulk(es, actions)
    except es_exceptions.ElasticsearchException as e:
        print(f"Error occurred while inserting data into Elasticsearch: {str(e)}")

# CONNECTIONS

from datetime import datetime
import paramiko
from elasticsearch import Elasticsearch, helpers, exceptions as es_exceptions

def get_connections_and_insert(hostname, username, password, es_url, es_user, es_pass, es_index):
    # Establishing Elasticsearch Connection
    es = Elasticsearch(
        [es_url],
        http_auth=(es_user, es_pass),
        verify_certs=False,
    )

    # List to hold the connection information.
    connections_info = []
    try:
        # SSH Client setup and connect.
        with paramiko.SSHClient() as client:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname, username=username, password=password)
            
            # Execute command and process output.
            stdin, stdout, stderr = client.exec_command('netstat -antup')
            lines = stdout.read().decode('utf-8').splitlines()
            for line in lines:
                # Skip non-data lines
                if not line.startswith(("tcp", "udp")):
                    continue
                fields = line.split()
                # Extracting fields and appending to connections_info
                proto = fields[0]
                recv_q = fields[1]
                send_q = fields[2]
                local_address, local_port = fields[3].rsplit(':', 1)
                foreign_address, foreign_port = fields[4].rsplit(':', 1)
                state = fields[5] if proto != 'udp' else 'N/A'
                pid = fields[-1].split('/')[0] if '/' in fields[-1] else 'N/A'
                connections_info.append({
                    "Proto": proto,
                    "Recv-Q": recv_q,
                    "Send-Q": send_q,
                    "Local Address": local_address,
                    "Local Port": local_port,
                    "Foreign Address": foreign_address,
                    "Foreign Port": foreign_port,
                    "State": state,
                    "PID": pid
                })

    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")

    # Get the current UTC time in ISO 8601 format
    timestamp = datetime.utcnow().isoformat()

    # Prepare Elasticsearch actions and perform bulk insert.
    actions = [
        {
            "_index": es_index,
            "_source": {
                "hostname": hostname,
                "timestamp": timestamp,
                **connection_info
            }
        }
        for connection_info in connections_info
    ]

    try:
        helpers.bulk(es, actions)
    except es_exceptions.ElasticsearchException as e:
        print(f"Error occurred while inserting data into Elasticsearch: {str(e)}")

# FAILED LOGINS - lastb command

def get_lastb_and_insert(hostname, username, password, es_url, es_user, es_pass, es_index):
    # Establishing Elasticsearch Connection
    es = Elasticsearch(
        [es_url],
        http_auth=(es_user, es_pass),
        verify_certs=False,
    )

    # List to hold the lastb information.
    lastb_info_list = []
    try:
        # SSH Client setup and connect.
        with paramiko.SSHClient() as client:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname, username=username, password=password)

            # Execute command and process output.
            command = 'sudo -S lastb'  # -S option makes sudo read password from stdin
            stdin, stdout, stderr = client.exec_command(command)
            stdin.write(password + '\n')  # Sending the sudo password
            stdin.flush()

            for line in stdout.read().decode('utf-8').splitlines():
                # Skip empty or unwanted lines
                if not line.strip() or 'btmp begins' in line:
                    continue

                # Parsing the data as needed
                fields = line.split()
                if len(fields) < 10:
                    print(f"Skipping malformed line: {line}")
                    continue

                user = fields[0]
                terminal = fields[1]
                ip_address = fields[2]
                # Concatenating fields to capture the entire time information
                time_info = " ".join(fields[3:7])
                lastb_info_list.append({
                    "user": user,
                    "terminal": terminal,
                    "ip_address": ip_address,
                    "time": time_info,
                })

    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")

    # Get the current UTC time in ISO 8601 format
    timestamp = datetime.utcnow().isoformat()

    # Prepare Elasticsearch actions and perform bulk insert.
    actions = [
        {
            "_index": es_index,
            "_source": {
                "hostname": hostname,
                "timestamp": timestamp,
                **lastb_info
            }
        }
        for lastb_info in lastb_info_list
    ]

    try:
        helpers.bulk(es, actions)
    except es_exceptions.ElasticsearchException as e:
        print(f"Error occurred while inserting data into Elasticsearch: {str(e)}")
