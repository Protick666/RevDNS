# DNSSEC Zone File Generator and Signer

This repository contains code to:
- Generate DNS zone files from CA-issued certificate serial numbers
- Sign the zones using DNSSEC
- Measure the signed zone file sizes for analysis

Before running the code, make sure the data/ folder contains the required input files. Your final structure should look like this:

data/
├── ca_to_sorted_serials_2025.json      # Mapping from CA name → list of certificate serial numbers
├── zone_source                         # Base zone template with a marker for where to insert TXT records
└── keys/
    ├── Kexample.com.+013+33003.key
    └── Kexample.com.+013+63150.key
The zone_source file is already included in this repository.

The key files (.key) used for DNSSEC signing must be placed in data/keys/.

The ca_to_sorted_serials_2025.json file is too large for direct upload to GitHub. Please download it from the following link and place it in the data/ directory:

https://drive.google.com/file/d/1aKGbCk8jjf-DYLifRRLzuZWvQH499cPB/view?usp=sharing

This JSON file contains the pre-processed, sorted serial numbers issued by each CA.


