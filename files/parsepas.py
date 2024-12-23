# program to parse a pasearch map and output put it as yaml
"""
Program to parse the pasearch output from z/OS to generate YAML of the non default options
"""
import argparse
import readfile
import readYAML


parser=argparse.ArgumentParser(description='Generate AT-TLS statements fromm YAML input',)

parser.add_argument("-o","--output",dest="po",default="./attls.report")
#parser.add_argument("-o2","--output2",dest="po2",default="./attls.2report")
parser.add_argument("-i","--input",dest="input",default="./pasearch.txt")
parser.add_argument("-d","--default",dest="default",default="./parsepasDefault.yaml")
#parser.add_argument("-c","--config",dest="config",default="./configattls.yaml")

args=parser.parse_args()


outputFileName  = args.po
#outputFileName2  = args.po2
defaultFileName = args.default

print("Output will be in",outputFileName)
print("Defaults from",defaultFileName)

fOutput = open(outputFileName,"w",encoding="utf-8")
#fOutput2 = open(outputFileName2,"w",encoding="utf-8")


policy = {}
policy_name = ""
previous = "Unknown"

#default2 = {}
"""
#fDefault = open("./default12.yaml")
#Default  = open("defaultFileName")
with open(defaultFileName) as fDefault:
    try:
        default = ruyaml.safe_load_all(fDefault)
        for d in default:
            for e in d:
                default2[e] = d[e]
    except ruyaml.YAMLError as exc:
        print(exc)

"""
default2 = readYAML.readYAML(defaultFileName)

defaultTLS12 ={}
for d,v  in default2.items(): # one off
    defaultTLS12[d] = v

defaultTLS13 = dict(defaultTLS12)
# add the tls 1.3 specific items


defaultTLS13["SignaturePairs"] = ["0601  TLS_SIGALG_SHA512_WITH_RSA",
    "0603  TLS_SIGALG_SHA512_WITH_ECDSA",
    "0501  TLS_SIGALG_SHA384_WITH_RSA",
    "0503  TLS_SIGALG_SHA384_WITH_ECDSA",
    "0401  TLS_SIGALG_SHA256_WITH_RSA",
    "0403  TLS_SIGALG_SHA256_WITH_ECDSA",
    "0402  TLS_SIGALG_SHA256_WITH_DSA",
    "0301  TLS_SIGALG_SHA224_WITH_RSA",
    "0303  TLS_SIGALG_SHA224_WITH_ECDSA",
    "0302  TLS_SIGALG_SHA224_WITH_DSA",
    "0201  TLS_SIGALG_SHA1_WITH_RSA",
    "0203  TLS_SIGALG_SHA1_WITH_ECDSA",
    "0202  TLS_SIGALG_SHA1_WITH_DSA",
    "0806  TLS_SIGALG_SHA512_WITH_RSASSA_PSS", 
    "0805  TLS_SIGALG_SHA384_WITH_RSASSA_PSS",   
    "0804  TLS_SIGALG_SHA256_WITH_RSASSA_PSS"]

defaultTLS13["ClientECurves"] = ['0021  secp224r1', '0023  secp256r1', '0024  secp384r1',
                                 '0025  secp521r1', '0019  secp192r1', '0029  X25519']

#
# Now the main processing reading the inputfiled
policy = readfile.readfile()

###
# Create a delta from the defaults, so we only show what is different
###

# import prettyprint
listNew = []
###
#  Create the delta
###
for policy_name,values in policy.items():
    # print("========="+policy_name+"====================",file=fOutput2)
    new = {}
    if "TLSv1.3" in values and values["TLSv1.3"] == "On":
        default = defaultTLS13
    else:
        default = defaultTLS12

    #TBA  default = getdefault_specific(default,p) # get the updated default for this item

    for each_value,citem in values.items():
     
        if isinstance(citem,int):
            citem = str(citem)
        #  Check to see if each item is in the default
        #  If not warn user and do next
        #  it is in default - so check the values, and ignore them if they match     
        if each_value not in default:
            print(each_value,"not found in default value:",citem)
            # not found, so update the current version
            new[each_value] = citem
            continue
        default_item = default[each_value]
     
        if isinstance(default_item,int):
            default_item = str(default_item)  # convert ints to strings so we can compare

        # Simple items
        if default_item == citem:
            continue   # do not default_itemsplay if they match

        if isinstance(default_item,dict) and isinstance(citem,dict):
            # go throught the current dict, and if the element is
            # the same as the default then remove it from the current
            # If current ends up empty then do not display it
            for i,v in default_item.items():
                if i in citem and v == citem[i]:
                    del citem[i]  # remove it as it is a defautl value
            if len(citem) == 0:
                continue # do not write it out...
            # for k in default_item:
            #     pass
            #     #print("==148,",k)
            if  each_value not in new:
                new[each_value] =[]
            new[each_value].append(citem)
        # This is for the timer data which can be a list
        if isinstance(default_item,dict) and isinstance(citem,list):
            #if each_value == "IpTimeCondition":
            #    print("==156",citem)
            for c in citem:  # each element in the list (is a dict)
                for i,v in default_item.items():
                   
                    if i in c and v == c[i]:
                        #if each_value == "IpTimeCondition":
                        #    print("==143",citem)
                        del c[i]  # remove it as it is a defautl value
                if len(c) == 0:
                    continue # do not write it out...
                #for k in default_item:
                #    #pass
                #    print("==168",k)
                # If this did not exist in the working version, add it as a list
                # So we can add more stuff to the list
                if  each_value not in new:
                    new[each_value] =[]
                new[each_value].append(c)
        elif citem != default_item:  # this should always be true if we got here
            new[each_value] = citem
    #  Save our working copy of the dict in the list of dicts
    listNew.append(new) 



needToQuote = ["\"","."," ", "(",")","{","}","*"]

for values in listNew:

    print("---",file=fOutput) # YAML delimeter
    for c in values:  
        v = values[c]

        if v is None:
            continue
        if v == "":
            continue
        if isinstance(v,str):
            o = v.strip()
            if any(e in o for e in needToQuote):
                o = "'"+o+"'" #  re.escape(o)
            print(c,":",o,file=fOutput)

        # IpTimeCondition is a list of dicts so need to iterate through
        # the list and do each dict
        elif c == "IpTimeCondition":
            print(c,": [",file=fOutput)
            for l in v:
                if isinstance(l,dict):                    
                    for ll in l:
                        print(" ",ll+":",l[ll],",",file=fOutput)
                else:
                    print("   "+l+",",file=fOutput)    # +re.escape(l))
            print("  ]",file=fOutput)
        elif isinstance(v,list):
            print(c,": [",file=fOutput)
            for l in v:
                print("   "+l+",",file=fOutput)    # +re.escape(l))
            print(" ]",file=fOutput)
        elif isinstance(v,dict):
            print(c,": ",file=fOutput)
            for l,l1 in v.items():
                print("   "+l+" : "+ l1+" ,",file=fOutput)    # +re.escape(l))
        else:
            print("Unknown object",c,v,file=fOutput)
            print("Unknown object",c,type(v),v)
        #print(type(values[c]),c,values[c])
