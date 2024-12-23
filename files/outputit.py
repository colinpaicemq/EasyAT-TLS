"""
Module to output the data from the pasearch source
"""
#import yaml
#mport sys
import ruyaml  # pip install ruamel.yaml

#lobal copy_parms
def proc(depth,dd,parms,rule_name):
    """
    Iterate over parts of the tree, outputting the data from the user's strucure
    """
    #rename = {"v3CipherSuites" : "V3CipherSuites"}
    depth = depth + 1
    output = list()
    #print("==10")
    #global copy_parms
    # dd is the partial tree of definitions
    #print("==13",dd)
    for d  in dd:
        v = dd[d]
        # print("==13",d,type(v),v)
        #if d == "V3CipherSuites":
        #    print("==15",v)
        #print("==17",d)

        if isinstance(v,dict):

            o = proc(depth,v,parms,rule_name)
            ol = len(o)
            if ol > 0:
                if d in ["TTLSEnvironmentAction","TTLSGroupAction","TTLSConnectionAction"]:
                    # print("==========?????Connection", d)
                    output.append(" " * depth +" "+ d + " " +d[4]+rule_name) # eg GCOLIN
                elif d == "TTLSRule":
                    # print("==========?????Connection", d)
                    output.append(" " * depth +" "+ d + " " +rule_name) # eg GCOLIN
                else:
                    output.append(" " + " " * depth + d )
                output.append(" " + " " * depth + "{" )
                for ol1 in o:
                    output.append(ol1)
                if d == "TTLSRule":
                    #print("==28 RLE",rule_name)
                    output.append("   "  + "TTLSEnvironmentActionRef E"+rule_name)
                    output.append("   "  + "TTLSGroupActionRef G"+rule_name)
                    output.append("   "  + "TTLSConnectionActionRef C"+rule_name)
                output.append(" " + " " * depth + "}" )
            #rint(" " * depth,"}")
        elif isinstance(v,list):
            print("===40",v)
            #
            # o = proc(depth,v,parms,rule_name)
            # ol = len(o)
            # if ol > 0:
            #     if d in ["TTLSEnvironmentAction","TTLSGroupAction","TTLSConnectionAction"]:
            #         # print("==========?????Connection", d)
            #         output.append(" " * depth +" "+ d + " " +d[4]+rule_name) # eg GCOLIN
            #     elif d == "TTLSRule":
            #         # print("==========?????Connection", d)
            #         output.append(" " * depth +" "+ d + " " +rule_name) # eg GCOLIN
            #     else:
            #         output.append(" " + " " * depth + d )
            #     output.append(" " + " " * depth + "{" )
            #     for ol1 in o:
            #         output.append(ol1)
            #     if d == "TTLSRule":
            #         #print("==28 RLE",rule_name)
            #         output.append("   "  + "TTLSEnvironmentActionRef E"+rule_name)
            #         output.append("   "  + "TTLSGroupActionRef G"+rule_name)
            #         output.append("   "  + "TTLSConnectionActionRef C"+rule_name)
            #     output.append(" " + " " * depth + "}" )
            # #rint(" " * depth,"}")
            #
        else  : #  isinstance(v,str):
            #print("==line38",d,v)
            if d in parms:

                if isinstance(parms[d],list):
                    #print("==80",d,parms[d])
                    for pp in parms[d]:
                        if isinstance(pp,dict):
                            #print("=83 list",pp)
                            output.append(" " * depth +" "  + d + " " )
                            output.append(" " * depth +" "  + "{" )
                            for a,b in  pp.items():
                                #print("==86",a,b)
                                if isinstance(b,int):
                                    b = str(b)
                                output.append(" " * depth + "   "  + a +" " +b)
                            output.append(" " * depth +" "  + " }" )
                        else:    
                            output.append(" " * depth +" " + d + pp[5:]   )

                else:
                    output.append(" " * depth +" "+ d + " " +parms[d])
                #del copy_parms[d]
                del parms[d]
        #else:
        #    print("==34 unepectd",d,v,type(v))
    return output



def outputit(inparm,rule_name):
    """
    Entry point to formatting at-tls data.  It calls a routine recursively
    to output the data
    """
    #print("==parms",inparm,rule_name)
    #global copy_parms
    copy_parms = inparm.copy()
    #print("====57",copy_parms["ServerCertificateLabel"])
    with open("./defaultrule2.yaml",encoding="utf-8") as file_default:
        try:
            default = ruyaml.safe_load_all(file_default)

            for e in default:
                #print("---99",e)
                #d = e["TTLSRule"]
                #global keyword_tree
                keyword_tree = e
                #for each in d:
                #   defaultDict[each] = d[each]

        except ruyaml.YAMLError as exc:
            print(exc)
    #print("==outputi",keyword_tree)
    output =  proc(0,keyword_tree,copy_parms,rule_name)
    #for k in keyword_tree:
    #    l =  keyword_tree[k]
    #    print("==24",type(k),k,l)
    for c in copy_parms:
        print("Unused",c,copy_parms[c])
    return output
