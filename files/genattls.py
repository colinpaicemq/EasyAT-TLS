#import yaml
"""
Generates AT-TLS definitions from YAML input file
"""
import sys
# import re


# import ttlsrule

import argparse
import ruyaml  # pip install ruamel.yaml
# import printit
import myMerge
import outputit
mydict = {}
parser=argparse.ArgumentParser(description='Generate AT-TLS statements fromm YAML input',)
parser.add_argument("-d","--default",dest='default',default="./defaultTree.yaml")
parser.add_argument("-i","--input",dest="inputFN",default="./new2.yaml")
parser.add_argument("-o","--output",dest="po",default="./attls.txt")
parser.add_argument("-b","--basedon",action="append")
args=parser.parse_args()


# parser.add_argument("-n","--name",dest="name")

defaultFileName=args.default
ruleName = ""
basedon = args.basedon
inputFN =  args.inputFN
poutput  = args.po
print("Output will be in",poutput)
if defaultFileName is None:
    print("-d filename is required - defauls to ./default12.yaml")
if inputFN is None:
    print("-i filename is needed default is ./new.yaml")
    sys.exit(0)
if poutput is None:
    print("-o filename is needed default is ./attls.txt")
hOutput = open(poutput, 'w',encoding="utf-8")
#fDefault = open(defautFileName)
# we do not need default -because they are all defaults!
defaultDict = {}
#  keywordTree() = dict()

# keyword tree is referenced in outputit

with open(defaultFileName,encoding="utf-8") as fDefault:
    try:
        default = ruyaml.safe_load_all(fDefault)
        for e in default:
            #d = e["TTLSRule"]
            #global keywordTree
            keywordTree = e
            #for each in d:
            #   defaultDict[each] = d[each]

    except ruyaml.YAMLError as exc:
        print(exc)
alldict = {}
#print("==65")
if basedon is not None:
    for  b in basedon:
        with open(b,encoding="utf-8") as stream:  # input default ./new.yaml
            try:
                dictionary = ruyaml.safe_load_all(stream)

                #print("after...")
                for d in dictionary:
                    dlist = {}
                    for key, value in d.items():  # each item in the list
                        if isinstance(value, int):
                            value = str(value)

                        if value is None:
                            print("Value is null for",key)
                            continue
                        dlist[key] = value

                    if 'policyRule' not in d:
                        print("policyRule  record not found in record",d)
                    else:
                        print(d["policyRule"])
                        alldict[d["policyRule"]] = dlist
            except ruyaml.YAMLError as exc:
                print(exc)

for a, v in alldict:
    print(a,v)


# merge the input data with any basedon... definitions
with open(inputFN,encoding="utf-8") as stream:  # input default ./new.yaml
    try:
        dictionary = ruyaml.safe_load_all(stream)

        #print("after...")
        for d in dictionary:
            if d is None:
                continue
            #print("new...",d)
            tempdata = {}
            #preset these to make the programming easier

            dlist = {} # dictionary for this instance

            if 'policyRule' not in d:
                print("policyRule  record not found in ",d)
            name = d['policyRule']

            for key, value in d.items():  # each item in the list
                if isinstance(value, int):
                    value = str(value)

                if value is None:
                    print("Value is null for",key)
                    continue
                #if key == "SignaturePairs":
                #     print("==123",key,type(value),value)

                dlist[key] = value

            if "BasedOn" in dlist:
                bo = dlist["BasedOn"]
                if isinstance(bo,str):   # make it into a list
                    bo = [bo]
                for bo0 in bo:
                    if bo0 not in mydict:
                        raise ValueError("BasedOn value not found:"+bo0)

                    baseItem  = mydict[bo0]
                    # copy from the total dict to ours
                    for baseKey, baseValue in baseItem.items():
                        tempdata[baseKey]  = baseValue
                    del dlist["BasedOn"] #


            # we need to do a clever merge, because we can have elements +item or -item or just item
            # depending on if you want to add, remove or replace
            # take the elements in the current list and merge with what we already have
            for baseKey, baseValue in dlist.items():
                if baseKey not in tempdata:
                    tempdata[baseKey] = []

                try:
                    tempdata[baseKey] = myMerge.myMerge(tempdata.get(baseKey),baseValue)
                except ValueError as e:
                    print("Exception line 106 ",e,"processing ",baseKey,baseValue)

            if "policyRule" in tempdata:

                ruleName = tempdata["policyRule"]
                del tempdata["policyRule"]
            # these can be lists of stringss...  convert to a string of 4 byte values
            # print("==160",i)
            for i in ["ClientECurves","ClientKeyShareGroups","ServerKeyShareGroups",
                      "ServerKexECurves","SignaturePairs","v3CipherSuites"]:
                # build up the string of 4 chars values, ignoring the long name
                #print("==164",i)
                if i in tempdata:
                    v = tempdata[i]
                    #print("===167",type(v))
                    if isinstance(v,str):
                        v = [v]
                    #print("===166",v)
                    v3 = ""
                    for vv in v:
                        #print("===170",vv)
                        v3 = v3+vv[0:4]
                        #print("===138",v3,vv)
                    tempdata[i]  = v3
                    #print("===173",v3)

            output = outputit.outputit(tempdata,ruleName)
            # display the final defintion
            print("##################"+ruleName+"===================",file=hOutput)
            for o1 in output:
                print(o1,file=hOutput)

            # update the master list in case we have inline based-ons
            mydict[ruleName] = tempdata


    except ruyaml.YAMLError as exc:
        print(exc)
