# BinCSV

BinCSV is a command line tool to create CSVs from binary files. Current support is Linux ELFs.


## Usage

To create a csv, run:

```bash
python3 -m bincsv <path-to-binary-file> <path-to-output-file.csv>
```


An example csv and configuration file is provided to create a CycloneDX SBOM using [csv2cdx](), by running:

```bash
cd example

csv2cdx -pn <sbom-name> -pv <sbom-version> -t application -c config_template.json -f <input-csv> -pt generic -ap True
```

