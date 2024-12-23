# EasyAT-TLS
Python programs to make it eaiser to create AT-TLS definition on z/OS - and to display the information

The official way of defining AT-TLS configuration requires the person to know a lot about the internal structure
of AT-TLS, and how configuration information is stored.

This project provides two functions

1. Formats the output of a pasearch report, and just reports the iteresting, non default information as a YAML format file.
1. Creates the AT-TLS definition file from YAML files, You specify the key data, and do not need to know the structure of the AT-TLS definitions.

## Extract the essence of the pasearch report 
Format

```
python3 parsepas.py <-d ./parsepasDefault.yaml> <-i ./pasearch.txt> <-o /attls.report>
```

Where 

- -d specified the default values from AT-TLS, see below for how it is used
- -i the input file name.  Download the output of the pasearch -t command from z/OS
- -o the output file name.


Step 1 of the program

The program reads the input file and builds a list of the rules in the source file.   Each element of the list is a Python dictionary of keyword and value.

For each element in the list, compare the elements of the dictionary with the defaults in the yaml file.  If the elements match, then do not display the item.  If the elements do not match, then display the item.

For example the defaults yaml file has LocalAddr : All.   If the value in the input data for LocalAddr is not "All" then output LocalAddr : value.

Using this technique the uninteresting data is not displayed, leaving the interesting data.

The output for one of my rules is
```
---
policyRule : AZFClientRule
Priority : 255
RemoteAddr : '0.0.26.137'
JobName : 'AZF*'
Direction : Outbound
HandshakeRole : Client
Trace : 255
Keyring : start1/TN3270
TLSv1.1 : Off
TLSv1.2 : On
TLSv1.3 : Off
TTLSEnabled : On
CertificateLabel : RSA2048
ServerCertificateLabel : RSA2048

```

In the pasearch file, the rule was 187 lines, so the output is very compact in comparison.

You can influence what is displayed, by editing the defaults yaml file.  For example I have
```
TLSv1 : Off
TLSv1.1 : 
```

If the value of TLSv1 is "Off" the data is not printed.   
Because there is no value for TLSv1.1, there will not be a match, and so the value will always be printed


## Generate AT-TLS definitions

The input is a yaml file, for example like the output displayed above, containing just the values of interest.
The program takes this yaml files and builds all of the AT-TLS stuff around it.

### Syntax

```
python3 genattls.py  <-i new2.yaml> <-o ./attls.txt>
```

Where

- -i is the input definition in yaml format
- -o is the name of the output file.

Internally a file ./defaultrule2.yaml is used.  This maps the statements in the input yaml file to the AT-TLS statements.

For example, the file has
```
TTLSConnectionAction:
  ...
  TTLSConnectionAdvancedParms : {SSLv2: , SSLv3: , TLSv1: , TLSv1.1: , TLSv1.2: ,
    TLSv1.3: , ServerCertificateLabel: Off, CertificateLabel: Off}
```

This is processed from top to bottom.
When processing the TTLSConnectionAction and TTLSConnectionAdvancedParms, if the TLSv1.1 is specified 
then write it it to the output file.

The input file containing

```
---
policyRule : AZFClientRule
Priority : 255
RemoteAddr : '0.0.26.137'
JobName : 'AZF*'
Direction : Outbound
HandshakeRole : Client
Trace : 255
Keyring : start1/TN3270
TLSv1.1 : Off
TLSv1.2 : On
TLSv1.3 : Off
TTLSEnabled : On
CertificateLabel : RSA2048
ServerCertificateLabel : RSA2048

```

Generates

```
  TTLSConnectionAction CAZFClientRule
  {
   TTLSConnectionAdvancedParms
   {
    TLSv1.1 Off
    TLSv1.2 On
    TLSv1.3 Off
    ServerCertificateLabel RSA2048
    CertificateLabel RSA2048
   }
  }

  ....

```

You can then upload the output file to z/OS and get policy agent to use your member

## Use of BasedOn

I found many of my definitions were very similar.  
In your input yaml you can specify BasedOn: name1, name2 containing defintions in yaml.

With the genattls.py you can specify one or more -b name.yaml. files which contain common definitions.  

For example  common.yaml has
```
# This first section is common to the others
policyRule : common
TLSv1.1 : Off
TLSv1.2 : On
TLSv1.3 : Off
Keyring : start1/TN3270
Priority : 255
LocalAddr : All
RemoteAddr : All
Direction : Inbound
TTLSEnabled : On
Trace : 255
Keyring : start1/TN3270
CertificateLabel : RSA2048
ServerCertificateLabel : RSA2048
---
```

This can be simplified by using "BasedOn" to refer to other sections, such as the "common" rule

---
# This first section is common to the others
policyRule : common
TLSv1.1 : Off
TLSv1.2 : On
TLSv1.3 : Off
Keyring : start1/TN3270
Priority : 255
LocalAddr : All
RemoteAddr : All
Direction : Inbound
TTLSEnabled : On
Trace : 255
Keyring : start1/TN3270
CertificateLabel : RSA2048
ServerCertificateLabel : RSA2048
---
policyRule : Rule1
BasedOn : common
LocalPortRange : 6794-6794
HandshakeRole : ServerWithClientAuth
HandshakeTimeout : 120
---
policyRule : Rule2
BasedOn : Rule1
LocalPortRange : 6793-6793
HandshakeRole : Server
---
```

You can put the "common" sections inline, or specify the file name containing them using the -b ... option.   You can specify -b .... repeatedly.

Within the input file you can specify BasedOn common1, common2 etc. and it will take first set of values from common1, then merge the definitions from common2, then merge the enties for the rule.

The definitions for Rule2 will be mostly the same as for Rule1, but LocalPortRange and HandshakeRole will be different.

