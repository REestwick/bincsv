import angr
import pandas as pd
import sys
import os

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
                    comp = {'name': val[0], 'version':val[1]}
                    dependencies.append(comp)
            check+=1
        else:
            check+=1
    return dependencies
        

#main 
def main(file, outfile):
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
        print(components_list)
        df = pd.DataFrame(components_list)
        df.drop_duplicates(inplace=True)
        df.to_csv(f"example/{outfile}", header=True, index=False)

                


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
