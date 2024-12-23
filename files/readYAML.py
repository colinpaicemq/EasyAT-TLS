"""
Read a yaml file into a dict
"""
import ruyaml  # pip install ruamel.yaml

def readYAML(name):
    """
    Read in a YAML file
    """
#  read in the based on file
    file = {}
    with open(name) as file_handle:
        try:
            default = ruyaml.safe_load_all(file_handle)
            for d in default:
                #print("==46",d)
                for e in d:
                    #print("==48",d,e)
                    file[e] = d[e]
        except ruyaml.YAMLError as exc:
            print(exc)
            raise
    #for x,y in file.items():
    #    print(x,y)
    return file
