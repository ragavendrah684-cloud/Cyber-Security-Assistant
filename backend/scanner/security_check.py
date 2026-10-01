import subprocess


def run_command(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout.strip()
    except Exception:
        return ""


def check_firewall():
    output = run_command(
        ["netsh", "advfirewall", "show", "allprofiles"]
    )

    if "State" in output and "ON" in output.upper():
        return "Enabled"

    if "State" in output and "OFF" in output.upper():
        return "Disabled"

    return "Unknown"


def check_antivirus():
    output = run_command(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-MpComputerStatus | "
            "Select-Object -ExpandProperty AntivirusEnabled"
        ]
    )

    if output.lower() == "true":
        return "Enabled"

    if output.lower() == "false":
        return "Disabled"

    return "Unknown"


def check_open_ports():
    output = run_command(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "(Get-NetTCPConnection -State Listen | "
            "Select-Object -ExpandProperty LocalPort | "
            "Sort-Object -Unique)"
        ]
    )

    if not output:
        return []

    ports = []

    for line in output.splitlines():
        line = line.strip()

        if line.isdigit():
            ports.append(int(line))

    return ports


def check_security():
    firewall = check_firewall()
    antivirus = check_antivirus()
    open_ports = check_open_ports()

    return {
        "firewall": firewall,
        "antivirus": antivirus,
        "open_ports": open_ports,
        "open_port_count": len(open_ports),
        "status": "Scan completed"
    }