import sys
from elasticsearch import Elasticsearch, helpers, exceptions as es_exceptions
import paramiko
from linux_enum_module import get_users_and_insert, get_groups_and_insert, get_processes_and_insert, get_shadow_and_insert, get_lastlog_and_insert

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
    get_users_and_insert(hostname, linux_user, linux_pass, es_url, es_user, es_pass, "hap-linux-users")
    get_groups_and_insert(hostname, linux_user, linux_pass, es_url, es_user, es_pass, "hap-linux-groups")
    get_processes_and_insert(hostname, linux_user, linux_pass, es_url, es_user, es_pass, 'hap-linux-processes')
    get_shadow_and_insert(hostname, linux_user, linux_pass, es_url, es_user, es_pass, 'hap-linux-shadow')
    get_lastlog_and_insert(hostname, linux_user, linux_pass, es_url, es_user, es_pass, 'hap-linux-lastlog')

