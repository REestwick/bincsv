import angr
import pandas as pd
import sys
import os
import csv2cdx.build
from pathlib import Path

#get binary name dependencies
def get_deps(dep):
    dependencies = []
    start = 2
    check = 0
    for key, val in dep.items():
        if check >= start:
            if '_' in val:
                val = val.split('_')
                if val[1][-1].isdigit() and val[1][0].isdigit():
                    name = val[0].lower()
                    version = val[1].lower()
                    comp = {
                            'name': name, 
                            'version':version
                            }
                    dependencies.append(comp)
            check+=1
        else:
            check+=1
    return dependencies
        

#main 
def main(file=sys.argv[1]):
    if not os.path.isfile(file):
        print("error: not a file") 
        exit(1)
    elif not os.path.exists(file):
        print("error: file does not exist")
    else:
        proj = angr.Project(file)
        proj.loader
        shared_obj = dict(proj.loader.shared_objects)
        count = 0 
        components_list = []
        for obj, val in  shared_obj.items():
            if ".so" in obj:
                components_list += get_deps(val._versions)
        df = pd.DataFrame(components_list)
        df.drop_duplicates(inplace=True, ignore_index=True)
        arg_data = {
                    "file": proj.filename.strip(),
                    "sbom_type": "application", 
                    "sbom_name": proj.filename.split("/")[-1], 
                    "sbom_version": sys.argv[2] if len(sys.argv) > 2 else "1.0.0", 
                    "package_type": "generic",
                    "add_purl": True
                }
        
        config_data = {
                        "api_url": None,
                        "component_configuration": {
                        "name": "name",
                        "version": "version"}
                        }
        
        build = csv2cdx.build.Builder(arg_data=arg_data, csv_data=df, json_data=config_data)
        build.build_sbom()


if __name__ == "__main__":
    main(sys.argv[1])
