"""
Read the input file and convert it to a list of dict items
"""
import argparse


def get_date(value):
    """
    Routine to convert a string date  Sun Jan  1 02:00:00 2012  into yyyymmddhmmss
    """
    t = value.replace(":"," ")
    t = t.split()
    m = ["x","Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"].index(t[1])
    m = str(m)
    m = m.rjust(2,"0")
    return t[6]+m+t[2].rjust(2,"0")+t[3]+t[4]+t[5]

def getdel(d,which):
    """
    Get from the dictionay and delete it
    """
    if which in d:
        v = d[which]
        del d[which]
    else:
        v = None
    return v

def readfile():
    """
    Read the input file and process it into a list of dicts
    """
    data = {}
    many = {"ServerKeyShareGroups","ServerKexECurves","SignaturePairs",
        "v3CipherSuites","ClientKeyShareGroups",
        "OcspRequestSigalg","ClientECurves", }
    two_entries = {}
    two_entries["Fr TimeOfDay"] = ["FromTod",24,29,"ToTOD",61,66]
    two_entries["Fr TimeOfDay UTC"] = ["FromTodUTC",24,29,"ToTODUTC",61,66]
    two_entries["TTLS Condition Summary"] = ["NegativeIndicator",61,6,"",0,0]
    two_entries["LocalPortFrom"] = ["LocalPortFrom",24,29,"LocalPortTo",61,69]
    two_entries["RemotePortFrom"] = ["RemotePortFrom",24,29,"RemotePortTo",61,69]
    two_entries["JobName"] = ["JobName",24,32,"UserId",61,68]
    #two_entries["Weight"] = ["Weight",24,32,"ForLoadDist",61,68]
    two_entries["Weight"] = ["Weight",24,32,"",0,0]
    two_entries["Priority"] = ["Priority",24,32,"",0,0]
    two_entries["Fr TimeOfDay"] = ["FromTOD",24,29,"ToTOD",61,66]
    #two_entries["Priority"] = ["Priority",24,32,"Sequence Actions",61,72]
    two_entries["Day of Week Mask"] =["Day of Week Mask",24,31,"",0,0]
    two_entries["Month of Yr Mask"] =["Month of Yr Mask",24,36,"",0,0]
    skip = ["TTLS Condition Summary","TTLS Instance Id","Date","Policy",
            "Policy created","Policy updated",
            "EnvironmentUserInstance","TTLS Action","ActionType",
            "No. Policy Action","Action Sequence",
            "policyAction","Scope","Weight","TTLSGroupAdvancedParms",
            "TTLSKeyringParms","TTLSSignatureParms",
            "TTLSConnectionAdvancedParms","TTLSGskOcspParms",
            "TTLSGskHttpCdpParms","TTLSGskAdvancedParms",
            "TTLSEnvironmentAdvancedParms","Day of Month Mask",
            "TTLSCipherParms","Time Periods","Day of Month Mask",
            "Start Date Time UTC","Fr TimeOfDay UTC","End Date Time UTC"]
    policy = {}
    policy_name = ""
    previous = "Unknown"

    # default2 = {}
    parser=argparse.ArgumentParser(description='Generate AT-TLS statements fromm YAML input',)
    parser.add_argument("-i","--input",dest="input",default="./pasearch.txt")
    args=parser.parse_args()
    input_file_name = args.input
    print("input file name:",input_file_name)

    file_input= open(input_file_name,encoding="ISO-8859-1")
    for line in file_input:
        #  We go through the file, adding lines into the dict called dict.
        #  When we get to a policy_name statement - we save the dict in policy
        #  and create a new dict
        line = line.rstrip()  # remove trailing blanks and new lines
        original_line = line  # save this for absolute positioning in the line  for twoentry
        line = line.strip() # remove leading blanks
        l = line.split(":",maxsplit=1)
        l0 = l[0]

        #
        # print(l)
        #do this one first because it reads the line
        if l0 == "policyRule":

            if policy_name != "":
                policy[policy_name] = data
                #print("==92",policy_name,data)
                data = dict()
                policy_name = l[1].strip()
            #
            else :
                policy_name = l[1].strip()

        # some entries have a name, followed by a list of values
        # we need to save the name, and if the next line is a valid content
        # add it to the list of the type
        if l0 in many:  # an array of many entries
            if l0 == "v3CipherSuites":
                l0 = "V3CipherSuites"
            #    #print("==111",l0)
            if l[1] != "":
                data[l0] = l[1].strip().rstrip()
            else:
                data[l0] = []
                previous = l0  # save name for next iteration
                #print("==117 previous now",previous)

        elif len(l) == 0:  # empty line
            continue
        elif len(l) == 1 and l == [""]:  # eg one of many
            continue
        elif len(l) == 1  :
            value = l[0].strip().rstrip()
            data[previous].append(value)


        elif l0.startswith("TCP/IP"):
            continue
        elif l0 in skip: # rows we are not interested in
            continue

        elif l0 == "ServiceDirection":
            data["Direction"] = l[1].strip().rstrip()
            #del data[l[0]]  # dont copy it
        # Local range has from address, followed by to address or range, so
        # we need to process the rows locally,
        elif l0 in ["Local Address","Remote Address"]:
            #addressType = "LocalAddr"
            #  Next line is  FromAddr:           ....
            line2 = file_input.readline()
            value = line2[24:].rstrip()
            # Next line is
            line2 = file_input.readline()
            line2 = line2.strip() # remove leading and trailing
            l = line2.split(":")
            l1= l[1].strip().rstrip()
            # print("==168",value,l1)
            if l[0] == "ToAddr":
                if l1 != value:  # so only one values specified
                    value  = value+"-"+l1
            elif l[0] == "Range":
                value  = value+"/"+l1
            elif l[0] == "Prefix":
                value  = value+"/"+l1
            else:
                print("Unexpected data in address",line2)
                value = "???"
            if l0 == "Local Address":
                data["LocalAddr"] = value
            else:
                data["RemoteAddr"] = value

        elif len(l) == 1:
            print("===170 no values",old)
            print("===171 no values",l)
            continue  # keyword with no value
        elif l[1] == "":  # eg Day of Month Mask:
            print("===173 no values",l)
            continue
        elif l0 == "TimeZone":

            ftl = getdel(data,"First to Last")
            ltf = getdel(data,"Last to First")
            mofy = getdel(data,"Month of Yr Mask")
            dow = getdel(data,"Day of Week Mask")
            sdmy = getdel(data,"Start Date Time")
            edmy = getdel(data,"End Date Time")
            ftod = getdel(data,"FromTOD")
            ttod = getdel(data,"ToTOD")

            tempdict = {}
            if ftl is not None:
                if ltf != "1"*31:  # conceteate non default
                    ftl = ftl + ltf
                tempdict["DayOfMonthMask"] = ftl
            if sdmy != "None":
                sdmy = get_date(sdmy)
                edmy = get_date(edmy)
                tempdict["ConditionTimeRange"] = sdmy+":"+edmy
            if mofy is not None:
                tempdict["MonthOfYearMask"] = mofy
            if dow is not None:
                tempdict["DayOfWeekMask"] = dow
            if ftod is not None:
                tempdict["TimeofDayRange"] = ftod+"-"+ttod
            # we can havemultiple timer entries so need a list rather than one off    
            if "IpTimeCondition" not in data:
                data["IpTimeCondition"] = [] # define a list
            data["IpTimeCondition"].append(tempdict)
            del tempdict
            #print("==194",len(data["IpTimeCondition"]))
            #for t in data["IpTimeCondition"]:
            #    print("==195",t)

        elif l0 in two_entries:
            parms = two_entries[l0]
            p1 = original_line[parms[1]:parms[2]].strip()
            data[parms[0]] = p1
            dp1 = "" # preset this
            if parms[4] > 0:  # more than one parameter in the
                dp1 = original_line[parms[4]:parms[5]].strip()
                data[parms[3]] = dp1
            if parms[0] == "LocalPortFrom":
                #if p1 not in ["0","All]":  # not the default
                if p1 != "0":  # not the default
                    data["LocalPortRange"] = p1+"-"+dp1  # eg 78-90
                del data[parms[0]]
                del data[parms[3]]
            elif parms[0] == "RemotePortFrom":
                #if p1 not in ["0","All]":  # not the default
                if p1 != "0":  # not the default
                    data["RemotePortRange"] = dp1+"-"+dp1  # eg 78-90
                del data[parms[0]]
                del data[parms[3]]

        else:
            data[l0]= l[1].strip().rstrip()

        old = line
    return policy
