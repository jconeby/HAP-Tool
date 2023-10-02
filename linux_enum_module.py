from datetime import datetime
import paramiko
from elasticsearch import Elasticsearch, helpers, exceptions as es_exceptions

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


from datetime import datetime
import paramiko
from elasticsearch import Elasticsearch, helpers, exceptions as es_exceptions


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
