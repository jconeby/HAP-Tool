import sys
import linux_enum_module as lem

if len(sys.argv) < 6:
    print("Usage: python3 enumerate_linux_users.py <hostnameString> <username> <password> <elasticURL> <elasticUsername> <elasticPassword>")
    sys.exit(1)

# Linux Creds
hostnames = sys.argv[1]
linux_user = sys.argv[2]
linux_pass = sys.argv[3]

# Elastic setup
es_url = sys.argv[4]
es_user = sys.argv[5]
es_pass = sys.argv[6]

for hostname in hostnames.split(','):
    lem.get_users_and_insert(hostname, linux_user, linux_pass, es_url, es_user, es_pass, 'hap-linux-users')
    lem.get_groups_and_insert(hostname, linux_user, linux_pass, es_url, es_user, es_pass, 'hap-linux-groups')
    lem.get_processes_and_insert(hostname, linux_user, linux_pass, es_url, es_user, es_pass, 'hap-linux-processes')
    lem.get_shadow_and_insert(hostname, linux_user, linux_pass, es_url, es_user, es_pass, 'hap-linux-shadow')
    lem.get_lastlog_and_insert(hostname, linux_user, linux_pass, es_url, es_user, es_pass, 'hap-linux-lastlog')
    lem.get_auth_logs_and_insert(hostname, linux_user, linux_pass, es_url, es_user, es_pass, 'hap-linux-authlog')
    lem.get_user_history_and_insert(hostname, linux_user, linux_pass, es_url, es_user, es_pass, 'hap-linux-history')
    lem.get_services_and_insert(hostname, linux_user, linux_pass, es_url, es_user, es_pass, 'hap-linux-services')
    lem.get_cron_jobs_and_insert(hostname, linux_user, linux_pass, es_url, es_user, es_pass, 'hap-linux-cronjobs')
    lem.get_hosts_and_insert(hostname, linux_user, linux_pass, es_url, es_user, es_pass, 'hap-linux-hosts')
    lem.get_connections_and_insert(hostname, linux_user, linux_pass, es_url, es_user, es_pass, 'hap-linux-connections')
    lem.get_lastb_and_insert(hostname, linux_user, linux_pass, es_url, es_user, es_pass, 'hap-linux-lastb')
    lem.get_meminfo_and_insert(hostname, linux_user, linux_pass, es_url, es_user, es_pass, 'hap-linux-memory')
    lem.get_internet_connections_and_insert(hostname, linux_user, linux_pass, es_url, es_user, es_pass, 'hap-linux-internet-connections')
    lem.get_unix_sockets_and_insert(hostname, linux_user, linux_pass, es_url, es_user, es_pass, 'hap-linux-unix-sockets')


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