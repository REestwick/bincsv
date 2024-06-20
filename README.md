# BinCSV

BinCSV is a command line tool to create an SBOM from binary files. Current support is Linux ELFs, and the binary must be a dynamic executable.


## Installation

* git clone this project 
* Run:
    ```bash
    cd bincsv
    pip install -e .
    ```


## Usage

To create an sbom, run:

```bash
python3 -m bincsv <path-to-binary-file>  <optional-binary-version>
```
You will get a CycloneDX formatted JSON file with the name ```your-binary-name_sbom.json```.
