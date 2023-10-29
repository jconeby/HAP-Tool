import re
import paramiko
from datetime import datetime

def get_boot_logs(hostname, username, password):
    logs_info = []
    timestamp = datetime.utcnow().isoformat()

    boot_pattern = re.compile(r'\[\s*(?P<status>.*?)\s*\]\s*(?P<action>Starting|Started|Reached|Listening|Stopped)?\s*(?P<service_desc>.+)')

    try:
        with paramiko.SSHClient() as client:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname, username=username, password=password)

            log_file = "/var/log/boot.log"
            log_name = "boot.log"
            command = f"sudo -S cat {log_file} && echo 'file_exists'"
            stdin, stdout, stderr = client.exec_command(command)
            stdin.write(f"{password}\n")
            stdin.flush()

            output = stdout.read().decode('utf-8').strip().splitlines()
            
            if "permission denied" in " ".join(output).lower() or not output:
                stdin, stdout, stderr = client.exec_command(f"cat {log_file}")
                output = stdout.read().decode('utf-8').strip().splitlines()

            for line in output:
                match = boot_pattern.match(line)
                if match:
                    logs_info.append({
                        "hostname": hostname,
                        "timestamp": timestamp,
                        "loginfo": line,
                        "logname": log_name,
                        "status": match.group("status"),
                        "action": match.group("action"),
                        "service_desc": match.group("service_desc")
                    })

    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname} using username {username}")
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection to {hostname}: {str(e)}")
    except Exception as e:
        print(f"Unexpected error occurred while connecting to {hostname}: {str(e)}")

    return logs_info

boot_logs = get_boot_logs("192.168.159.202", "assessor", "cyberbattle31337")
print(boot_logs)
