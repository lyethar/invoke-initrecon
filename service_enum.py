import os
import re
import subprocess


def get_nmap_targets():
    """
    Parses files in the current directory matching 'tcp_<port>-<service>.txt'
    and returns a list of (port, filename) tuples.
    """
    pattern = re.compile(r"tcp_(\d+)-[\w\d]+\.txt")
    targets = []
    for fname in os.listdir("."):
        match = pattern.match(fname)
        if match:
            targets.append((match.group(1), fname))
    return targets


def _run_nmap(extra_args, targets, label):
    if not targets:
        print("No valid target files found.")
        return

    for port, filename in targets:
        output_file = f"{label}_output_{port}"
        cmd = ["nmap", "-Pn", "-n"] + extra_args + ["-p", port, "-iL", filename, "-oA", output_file]
        print(f"Running: {' '.join(cmd)}")
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as exc:
            print(f"Error running nmap for {filename}: {exc}")


def run_nmap_service_scan(targets=None):
    if targets is None:
        targets = get_nmap_targets()
    _run_nmap(["-sV"], targets, "service")


def run_nmap_script_scan(targets=None):
    if targets is None:
        targets = get_nmap_targets()
    _run_nmap(["-sC"], targets, "script")


if __name__ == "__main__":
    targets = get_nmap_targets()
    run_nmap_service_scan(targets)
    run_nmap_script_scan(targets)
