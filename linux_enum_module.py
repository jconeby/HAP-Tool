from datetime import datetime
import paramiko
import requests
import json
import base64
import re

# SEND DATA TO ELASTIC

def send_to_elasticsearch(data, es_url, index_name, es_user, es_pass):
    # pass base64 credentials in the header
    credentials = base64.b64encode(f"{es_user}:{es_pass}".encode()).decode()

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {credentials}"
    }
    
    # Bulk indexing URL for Elasticsearch
    bulk_url = f"{es_url}/{index_name}/_bulk"
    
    bulk_data = ""
    for item in data:
        # The action and metadata line
        bulk_data += json.dumps({"index": {}}) + "\n"
        # The actual data
        bulk_data += json.dumps(item) + "\n"
    
    response = requests.post(bulk_url, headers=headers, data=bulk_data, verify=False)
    
    if response.status_code != 200:
        print(f"Failed to insert data into Elasticsearch. Response: {response.text}")


# PROCESSES

def get_running_processes(hostname, username, password):
    processes_info = []
    
    # Get the current UTC time in ISO 8601 format
    timestamp = datetime.utcnow().isoformat()

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
                    "hostname": hostname,
                    "timestamp": timestamp,
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
    
    return processes_info


# LOCAL USERS

def get_users(hostname, username, password):
    # List to hold the user information.
    users_info = []
    
    # Get the current UTC time in ISO 8601 format
    timestamp = datetime.utcnow().isoformat()

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
                users_info.append({
                    "hostname": hostname,
                    "timestamp": timestamp,
                    "user": user, 
                    "userinfo": line
                })
                
    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")
    
    return users_info


# LOCAL GROUPS

def get_groups(hostname, username, password):
    # List to hold the group information.
    groups_info = []
    
    # Get the current UTC time in ISO 8601 format
    timestamp = datetime.utcnow().isoformat()

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
                groups_info.append({
                    "hostname": hostname,
                    "timestamp": timestamp,
                    "group": group,
                    "groupinfo": line
                })
                
    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")
    
    return groups_info


# /etc/shadow Contents

def get_shadow(hostname, username, password):
    # List to hold the shadow information.
    shadow_info_list = []
    
    # Get the current UTC time in ISO 8601 format
    timestamp = datetime.utcnow().isoformat()

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
                shadow_info_list.append({
                    "hostname": hostname,
                    "timestamp": timestamp,
                    "user": user,
                    "shadow_info": line
                })
                
    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")
    
    return shadow_info_list

# LASTLOG

import paramiko
from datetime import datetime

def get_lastlog(hostname, username, password):
    # List to hold the lastlog information.
    lastlog_info = []
    
    # Get the current UTC time in ISO 8601 format
    timestamp = datetime.utcnow().isoformat()

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
                    "hostname": hostname,
                    "timestamp": timestamp,
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
    
    return lastlog_info


# AUTH LOGS - This function is to identify any odd SSH & Telent logins

def get_auth_logs(hostname, username, password):
    
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
                logs_info.append({
                    "hostname": hostname,
                    "loginfo": line,
                    "timestamp": datetime.utcnow().isoformat()
                })
                
    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")

    return logs_info


# BASH HISTORY

def get_user_history(hostname, username, password):
    """ Fetches the bash history for all users on the given host. """
    
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
                history_info.append({
                    "hostname": hostname,
                    "user": user.strip(),
                    "command": cmd.strip(),
                    "history_info": line.strip(),
                    "timestamp": datetime.utcnow().isoformat()
                })
                
    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")
    
    return history_info


# SERVICES

def get_services(hostname, username, password):
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
                
                # Get the current UTC time in ISO 8601 format
                timestamp = datetime.utcnow().isoformat()
                
                services_info.append({
                    "hostname": hostname,
                    "service": service,
                    "status": status,
                    "serviceinfo": line.strip(),
                    "timestamp": timestamp
                })
                
    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")
    
    return services_info


# CRONJOBS

def get_cron_jobs(hostname, username, password):
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

                        # Get the current UTC time in ISO 8601 format
                        cron_job["timestamp"] = datetime.utcnow().isoformat()
                        cron_job["hostname"] = hostname

                        cron_jobs_info.append(cron_job)

    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")
    
    return cron_jobs_info


# Get the /etc/hosts file

def get_hosts(hostname, username, password):
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
                                # Structured host_info
                                host_data = {
                                    "ip_address": ip_address,
                                    "host": host,
                                    "timestamp": datetime.utcnow().isoformat(),
                                    "hostname": hostname
                                }
                                hosts_info.append(host_data)

    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")

    return hosts_info


# CONNECTIONS

def get_connections(hostname, username, password):

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

                connection_data = {
                    "Proto": proto,
                    "Recv-Q": recv_q,
                    "Send-Q": send_q,
                    "Local Address": local_address,
                    "Local Port": local_port,
                    "Foreign Address": foreign_address,
                    "Foreign Port": foreign_port,
                    "State": state,
                    "PID": pid,
                    "timestamp": datetime.utcnow().isoformat(),
                    "hostname": hostname
                }
                connections_info.append(connection_data)

    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")

    return connections_info


# FAILED LOGINS

def get_lastb(hostname, username, password):

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
                lastb_data = {
                    "user": user,
                    "terminal": terminal,
                    "ip_address": ip_address,
                    "time": time_info,
                    "timestamp": datetime.utcnow().isoformat(),
                    "hostname": hostname
                }
                lastb_info_list.append(lastb_data)

    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")

    return lastb_info_list

# MEMORY INFO

def get_meminfo(hostname, username, password):

    mem_info = {}

    try:
        # SSH Client setup and connect.
        with paramiko.SSHClient() as client:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname, username=username, password=password)
            
            # Execute command and process output.
            stdin, stdout, stderr = client.exec_command('cat /proc/meminfo')
            for line in stdout.read().decode('utf-8').splitlines():
                key, value = line.split(":")
                mem_info[key.strip()] = value.strip()

    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")

    return {
        "hostname": hostname,
        "timestamp": datetime.utcnow().isoformat(),
        "meminfo": mem_info
    }

# ACTIVE INTERNET CONNECTIONS

def get_internet_connections(hostname, username, password):
    
    connections_info = []

    try:
        # SSH Client setup and connect.
        with paramiko.SSHClient() as client:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname, username=username, password=password)
            
            # Execute command and process output.
            stdin, stdout, stderr = client.exec_command('netstat -anp')
            lines = stdout.read().decode('utf-8').splitlines()
            parse_active = False  # Add flag to start parsing after active connections header
            for line in lines:
                if "Active Internet connections" in line:
                    parse_active = True
                    continue  # skip header line
                if "Active UNIX domain sockets" in line:
                    break  # stop parsing after internet connections section
                if parse_active and line.startswith(("tcp", "udp")):
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
                        "PID": pid,
                        "timestamp": datetime.utcnow().isoformat()
                    })

    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")

    return connections_info


# UNIX SOCKETS - unix section of the netstat -anp command

def get_unix_sockets_info(hostname, username, password):
    # List to hold the socket information.
    unix_sockets_info = []

    try:
        # SSH Client setup and connect.
        with paramiko.SSHClient() as client:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname, username=username, password=password)
            
            # Execute command and process output.
            stdin, stdout, stderr = client.exec_command('netstat -anp')
            lines = stdout.read().decode('utf-8').splitlines()
            parse_unix = False

            for line in lines:
                if "Active UNIX domain sockets" in line:
                    parse_unix = True
                    continue
                if parse_unix and line.startswith("unix"):
                    # Extracting fields considering square brackets and optional path
                    pattern = re.compile(r'(\S+)\s+(\S+)\s+\[\s*(\S*)\s*\]\s+(\S+)\s+(\S+)\s+(\S+)\s+(-|\d+/[^ ]+)(?:\s+([^ ]+))?')
                    match = pattern.match(line)
                    if match:
                        pid_program = match.group(7).split('/')
                        if len(pid_program) == 2:
                            pid, program = pid_program
                        else:
                            pid, program = pid_program[0], 'N/A'

                        unix_sockets_info.append({
                            "Proto": match.group(1),
                            "RefCnt": match.group(2),
                            "Flags": match.group(3),
                            "Type": match.group(4),
                            "State": match.group(5),
                            "I-Node": match.group(6),
                            "PID": pid,
                            "Program name": program,
                            "Path": match.group(8) if match.group(8) else 'N/A',
                            "hostname": hostname,
                            "timestamp": datetime.utcnow().isoformat(),
                        })

    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
        return []
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
        return []
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")
        return []

    return unix_sockets_info


# CREATE INDEX PATTERNS
def create_index_pattern(elastic_url, elastic_user, elastic_pass, index_pattern):
    
    # Define the URL for checking and creating the index pattern in the .kibana index
    index_pattern_endpoint = f"{elastic_url}/.kibana/_doc/index-pattern:{index_pattern}"

    # Send a GET request to check if the index pattern already exists
    check_response = requests.get(
        index_pattern_endpoint, 
        auth=(elastic_user, elastic_pass),
        verify=False  # Note: Insecure, see note below.
    )

    # If a document with the index pattern ID already exists, exit the function
    if check_response.status_code == 200:
        return check_response
    
    # Define the payload for the POST request
    data = {
        "type": "index-pattern",
        "index-pattern": {
            "title": index_pattern,
            "timeFieldName": "timestamp"
        }
    }
    
    # Send the POST request to create the index pattern
    create_response = requests.post(
        index_pattern_endpoint, 
        auth=(elastic_user, elastic_pass),
        headers={"Content-Type": "application/json"}, 
        data=json.dumps(data), 
        verify=False  # Note: Insecure, see note below.
    )
    
    # Return the response object for further inspection (e.g., check status_code)
    return create_response
