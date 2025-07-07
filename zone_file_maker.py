import os
import json
import subprocess
from pathlib import Path
from collections import defaultdict
from multiprocessing import Pool

# Algorithm to DNSSEC key file mappings
# Ensure these files exist under `/data/keys/`
algo_to_keys = {
    "ECDSA_256": ["Kexample.com.+013+33003.key", "Kexample.com.+013+63150.key"]
}

def get_leaf_files(path):
    """Recursively collect all file paths under `path`."""
    return [os.path.join(root, file)
            for root, _, files in os.walk(path) for file in files]

def sanitize_ca(ca):
    """Replace unsafe characters in CA names for file paths."""
    return ca.replace(" ", "-").replace("/", "-")

def change_zone_file(serial_list, ca):
    """Generate zone file per CA and algorithm."""
    source_file = "/data/zone_source"  # Template zone file
    keys_dir = "/data/keys"
    output_base = "/data/zones"

    with open(source_file) as f:
        lines = f.readlines()

    insert_index = next(i for i, line in enumerate(lines) if '; Other TXT records' in line) + 1
    serial_txts = [f"{serial} IN TXT \"revoke\"\n" for serial in serial_list]
    lines[insert_index:insert_index] = serial_txts  # Inject serial records

    for algo, key_files in algo_to_keys.items():
        zone_lines = lines.copy()
        zone_lines += [f"$INCLUDE {os.path.join(keys_dir, key)}\n" for key in key_files]

        ca_path = os.path.join(output_base, algo, sanitize_ca(ca))
        Path(ca_path).mkdir(parents=True, exist_ok=True)
        dest_file = os.path.join(ca_path, "example.com.zone")

        with open(dest_file, "w") as f:
            f.writelines(zone_lines)

def make_zone_files():
    """Load serials and create zone files."""
    input_json = "/data/ca_to_sorted_serials_2025.json"
    with open(input_json) as f:
        ca_to_serials = json.load(f)

    for ca, serials in ca_to_serials.items():
        change_zone_file(serials, ca)

def execute_cmd(command):
    """Run shell command and return output."""
    process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    return output.decode(), error

def sign_zone_file(file):
    """Sign a zone file with dnssec-signzone."""
    try:
        cmd = f"dnssec-signzone -N INCREMENT -o example.com -t {file}"
        output, error = execute_cmd(cmd)
        print(f"Signed {file}")
    except Exception as e:
        print(f"Error signing {file}: {e}")
        output = str(e)

    return file, output

def sign_zone_files():
    """Find zone files and sign them in parallel."""
    files = get_leaf_files("/data/zones")
    zone_files = [f for f in files if f.endswith(".zone")]

    results = {}
    with Pool() as pool:
        for file, output in pool.imap_unordered(sign_zone_file, zone_files):
            results[file] = output

    with open("/data/signing_output.json", "w") as f:
        json.dump(results, f)

def get_file_sizes():
    """Measure signed file sizes and store them by CA and algorithm."""
    files = get_leaf_files("/data/zones")
    size_map = defaultdict(lambda: defaultdict(float))

    for file in files:
        if not file.endswith(".signed"):
            continue
        *_, algo, ca, _ = file.split("/")[-4:]
        size_map[ca][algo] = os.path.getsize(file) / 1e6  # in MB

    with open("/data/dnssec_file_size_2025.json", "w") as f:
        json.dump(size_map, f)

    with open("/data/dnssec_file_size_indented_2025.json", "w") as f:
        json.dump(size_map, f, indent=2)

if __name__ == "__main__":
    make_zone_files()
    sign_zone_files()
    get_file_sizes()
