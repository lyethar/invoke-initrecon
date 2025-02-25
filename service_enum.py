import os
import re
import subprocess

def get_nmap_targets():
    """
    Parses files in the current directory with the format 'tcp_<port>-<service>.txt'
    and returns a list of (port, filename) tuples.
    """
    files = os.listdir(".")
    pattern = re.compile(r"tcp_(\d+)-[\w\d]+\.txt")  # Regex to match the expected file format
    
    targets = []
    for file in files:
        match = pattern.match(file)
        if match:
            port = match.group(1)
            targets.append((port, file))
    
    return targets

def run_nmap_scan():
    """
    Runs nmap scan for each parsed target file.
    """
    targets = get_nmap_targets()
    
    if not targets:
        print("No valid target files found.")
        return

    for port, filename in targets:
        output_file = f"output_{port}"
        cmd = [
            "nmap", "-Pn", "-n", "-sV", "-p", port,
            "-iL", filename, "-oA", output_file
        ]
        print(f"Running: {' '.join(cmd)}")
        
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error running Nmap for {filename}: {e}")

if __name__ == "__main__":
    run_nmap_scan()
