import sys
import linux_enum_module as lem

# Validate arguments
if len(sys.argv) < 6:
    print("Usage: python3 enumerate_linux_users.py <hostnameString> <username> <password> <elasticURL> <elasticUsername> <elasticPassword>")
    sys.exit(1)

# Linux Creds
hostnames = sys.argv[1].split(',')
linux_user = sys.argv[2]
linux_pass = sys.argv[3]

# Elastic setup
es_url = sys.argv[4]
es_user = sys.argv[5]
es_pass = sys.argv[6]

# Define a mapping for information to gather and their corresponding functions and Elasticsearch index
info_mapping = {
    "processes": (lem.get_running_processes, "hap-linux-processes"),
    "users": (lem.get_users, "hap-linux-users"),
    "groups": (lem.get_groups, "hap-linux-groups"),
    "shadow": (lem.get_shadow, "hap-linux-shadow"),
    "lastlog": (lem.get_lastlog, "hap-linux-lastlog"),
    "authlogs": (lem.get_auth_logs, "hap-linux-authlog"),
    "history": (lem.get_user_history, "hap-linux-history"),
    "services": (lem.get_services, "hap-linux-services"),
    "cronjobs": (lem.get_cron_jobs, "hap-linux-cronjobs"),
    "hosts": (lem.get_hosts, "hap-linux-hosts"),
    "lastb": (lem.get_lastb, "hap-linux-lastb"),
    "memory": (lem.get_meminfo, "hap-linux-memory"),
    "connections": (lem.get_connections, "hap-linux-connections"),
    "internet": (lem.get_internet_connections, "hap-linux-internet-connections"),
    "sockets": (lem.get_unix_sockets_info, "hap-linux-unix-sockets"),
}

for key, (gather_func, es_index) in info_mapping.items():
    all_info = []

    for hostname in hostnames:
        info = gather_func(hostname, linux_user, linux_pass)
        if info:  # Check if the list is not empty
            all_info.extend(info)
    
    # Only send data to Elasticsearch if there's something to send
    if all_info:
        lem.send_to_elasticsearch(all_info, es_url, es_index, es_user, es_pass)

# List of all index patterns used by the script
index_patterns = [
    'hap-linux-users', 'hap-linux-groups', 'hap-linux-processes', 'hap-linux-shadow',
    'hap-linux-lastlog', 'hap-linux-authlog', 'hap-linux-history', 'hap-linux-services',
    'hap-linux-cronjobs', 'hap-linux-hosts', 'hap-linux-connections', 'hap-linux-lastb',
    'hap-linux-memory', 'hap-linux-internet-connections', 'hap-linux-unix-sockets'
]

# Ensure all index patterns exist and if not create them
for index_pattern in index_patterns:
    lem.create_index_pattern(es_url, es_user, es_pass, index_pattern)