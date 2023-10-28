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
    "authlogs": (lem.get_auth_logs, "hap-linux-authlog"),
    "securelogs": (lem.get_secure_logs, "hap-linux-authlog"),
    "messagelogs": (lem.get_messages_logs, "hap-linux-messages"),
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
    'hap-linux-authlog', 'hap-linux-messages', 'crew_log'
]

# Ensure all index patterns exist and if not create them
for index_pattern in index_patterns:
    lem.create_index_pattern(es_url, es_user, es_pass, index_pattern)

# Log that the script was ran in Elastic
lem.log_script_execution_to_elastic(es_url, es_user, es_pass, ','.join(hostnames))