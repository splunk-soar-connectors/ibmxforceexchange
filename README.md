[comment]: # "Auto-generated SOAR connector documentation"
# IBM X\-Force Exchange

Publisher: Splunk  
Connector Version: 1\.1\.1  
Product Vendor: IBM  
Product Name: IBM X\-Force Exchange  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.2\.0  

This app implements various 'investigative' actions on the 'IBM X\-Force Exchange' device

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a IBM X\-Force Exchange asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  required  | string | X\-Force Base URL
**verify\_cert** |  optional  | boolean | Verify Server Certificate
**api\-key** |  required  | password | X\-Force API Key
**api\-password** |  required  | password | X\-Force API Password

### Supported Actions  
[ip reputation](#action-ip-reputation) - Returns IP reputation report  
[domain reputation](#action-domain-reputation) - Returns domain reputation report  
[whois domain](#action-whois-domain) - Returns WHOIS report  
[whois ip](#action-whois-ip) - Returns WHOIS report  
[url reputation](#action-url-reputation) - Returns URL reputation report  
[file reputation](#action-file-reputation) - Returns malware report for a given hash  
[test connectivity](#action-test-connectivity) - Validates connectivity to XForce  

## action: 'ip reputation'
Returns IP reputation report

Type: **investigate**  
Read only: **False**

Runs the X\-Force IP Report, IP Malware Report, and DNS Lookup\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP Address to Investigate | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.summary\.score | string | 
action\_result\.summary\.category | string | 
action\_result\.summary\.country | string | 
action\_result\.summary\.earliest\_entry | string | 
action\_result\.summary\.latest\_entry | string | 
action\_result\.summary\.subnets | string | 
action\_result\.summary\.malware\_observed | numeric | 
action\_result\.summary\.malware\_last\_90 | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.xforce\_ip\_report\.score | numeric | 
action\_result\.data\.\*\.xforce\_ip\_report\.ip | string |  `ip` 
action\_result\.data\.\*\.xforce\_ip\_report\.reason | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.reasonDescription | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.geo\.country | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.geo\.countrycode | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.categoryDescriptions\.\*\.category | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.categoryDescriptions\.\*\.description | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.cats\.\*\.category | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.cats\.\*\.percentage | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.subnets\.\*\.subnet | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.subnets\.\*\.reason | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.subnets\.\*\.reasonDescription | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.subnets\.\*\.created | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.subnets\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.xforce\_ip\_report\.subnets\.\*\.score | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.subnets\.\*\.geo\.country | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.subnets\.\*\.geo\.countrycode | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.subnets\.\*\.categoryDescriptions\.\*\.category | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.subnets\.\*\.categoryDescriptions\.\*\.description | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.history\.\*\.score | numeric | 
action\_result\.data\.\*\.xforce\_ip\_report\.history\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.xforce\_ip\_report\.history\.\*\.reason | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.history\.\*\.reasonDescription | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.history\.\*\.geo\.country | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.history\.\*\.geo\.countrycode | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.history\.\*\.categoryDescriptions\.\*\.category | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.history\.\*\.categoryDescriptions\.\*\.description | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.history\.cats\.\*\.category | string | 
action\_result\.data\.\*\.xforce\_ip\_report\.history\.cats\.\*\.percentage | string | 
action\_result\.data\.\*\.xforce\_ip\_malware\.malware\.\*\.type | string | 
action\_result\.data\.\*\.xforce\_ip\_malware\.malware\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.xforce\_ip\_malware\.malware\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.xforce\_ip\_malware\.malware\.\*\.firstseen | string | 
action\_result\.data\.\*\.xforce\_ip\_malware\.malware\.\*\.lastseen | string | 
action\_result\.data\.\*\.xforce\_ip\_malware\.malware\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.xforce\_ip\_malware\.malware\.\*\.count | numeric | 
action\_result\.data\.\*\.xforce\_ip\_malware\.malware\.\*\.filepath | string |  `file path` 
action\_result\.data\.\*\.xforce\_ip\_malware\.malware\.\*\.first | string | 
action\_result\.data\.\*\.xforce\_ip\_malware\.malware\.\*\.last | string | 
action\_result\.data\.\*\.xforce\_ip\_malware\.malware\.\*\.origin | string | 
action\_result\.data\.\*\.xforce\_ip\_malware\.malware\.\*\.family\.\*\.name | string | 
action\_result\.data\.\*\.xforce\_dns\.A\.\*\.record | string |  `ip` 
action\_result\.data\.\*\.xforce\_dns\.AAAA\.\*\.record | string |  `ip` 
action\_result\.data\.\*\.xforce\_dns\.TXT\.\*\.\*\.record | string | 
action\_result\.data\.\*\.xforce\_dns\.MX\.\*\.exchange | string | 
action\_result\.data\.\*\.xforce\_dns\.MX\.\*\.priority | string | 
action\_result\.data\.\*\.xforce\_dns\.total\_rows | numeric | 
action\_result\.data\.\*\.xforce\_dns\.Passive\.query | string | 
action\_result\.data\.\*\.xforce\_dns\.Passive\.records\.\*\.value | string | 
action\_result\.data\.\*\.xforce\_dns\.Passive\.records\.\*\.type | string | 
action\_result\.data\.\*\.xforce\_dns\.Passive\.records\.\*\.recordType | string | 
action\_result\.data\.\*\.xforce\_dns\.Passive\.records\.\*\.first | string | 
action\_result\.data\.\*\.xforce\_dns\.Passive\.records\.\*\.last | string |   

## action: 'domain reputation'
Returns domain reputation report

Type: **investigate**  
Read only: **False**

Runs the X\-Force URL Report and URL Malware Report \(both of which accept domains\), and DNS Lookup\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query\_value** |  required  | Domain to Investigate | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.query\_value | string |  `domain`  `url` 
action\_result\.summary\.score | string | 
action\_result\.summary\.category | string | 
action\_result\.summary\.malware\_observed | numeric | 
action\_result\.summary\.malware\_last\_90 | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.xforce\_url\_report\.result\.score | numeric | 
action\_result\.data\.\*\.xforce\_url\_report\.result\.url | string |  `domain` 
action\_result\.data\.\*\.xforce\_url\_report\.result\.categoryDescriptions\.\*\.category | string | 
action\_result\.data\.\*\.xforce\_url\_report\.result\.categoryDescriptions\.\*\.description | string | 
action\_result\.data\.\*\.xforce\_url\_report\.result\.cats\.\*\.category | string | 
action\_result\.data\.\*\.xforce\_url\_report\.result\.cats\.\*\.percentage | string | 
action\_result\.data\.\*\.xforce\_url\_report\.result\.score | numeric | 
action\_result\.data\.\*\.xforce\_url\_report\.associated\.\*\.url | string |  `url` 
action\_result\.data\.\*\.xforce\_url\_report\.associated\.\*\.categoryDescriptions\.\*\.category | string | 
action\_result\.data\.\*\.xforce\_url\_report\.associated\.\*\.categoryDescriptions\.\*\.description | string | 
action\_result\.data\.\*\.xforce\_url\_report\.associated\.cats\.\*\.category | string | 
action\_result\.data\.\*\.xforce\_url\_report\.associated\.cats\.\*\.percentage | string | 
action\_result\.data\.\*\.xforce\_url\_malware\.malware\.\*\.type | string | 
action\_result\.data\.\*\.xforce\_url\_malware\.malware\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.xforce\_url\_malware\.malware\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.xforce\_url\_malware\.malware\.\*\.firstseen | string | 
action\_result\.data\.\*\.xforce\_url\_malware\.malware\.\*\.lastseen | string | 
action\_result\.data\.\*\.xforce\_url\_malware\.malware\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.xforce\_url\_malware\.malware\.\*\.count | numeric | 
action\_result\.data\.\*\.xforce\_url\_malware\.malware\.\*\.filepath | string |  `file path` 
action\_result\.data\.\*\.xforce\_url\_malware\.malware\.\*\.origin | string | 
action\_result\.data\.\*\.xforce\_url\_malware\.malware\.\*\.family\.\*\.name | string | 
action\_result\.data\.\*\.xforce\_dns\.A\.\*\.record | string |  `ip` 
action\_result\.data\.\*\.xforce\_dns\.AAAA\.\*\.record | string |  `ip` 
action\_result\.data\.\*\.xforce\_dns\.TXT\.\*\.\*\.record | string | 
action\_result\.data\.\*\.xforce\_dns\.MX\.\*\.exchange | string | 
action\_result\.data\.\*\.xforce\_dns\.MX\.\*\.priority | string | 
action\_result\.data\.\*\.xforce\_dns\.total\_rows | numeric | 
action\_result\.data\.\*\.xforce\_dns\.Passive\.query | string | 
action\_result\.data\.\*\.xforce\_dns\.Passive\.records\.\*\.value | string | 
action\_result\.data\.\*\.xforce\_dns\.Passive\.records\.\*\.type | string | 
action\_result\.data\.\*\.xforce\_dns\.Passive\.records\.\*\.recordType | string | 
action\_result\.data\.\*\.xforce\_dns\.Passive\.records\.\*\.first | string | 
action\_result\.data\.\*\.xforce\_dns\.Passive\.records\.\*\.last | string |   

## action: 'whois domain'
Returns WHOIS report

Type: **investigate**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query\_value** |  required  | Domain to Investigate | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.query\_value | string |  `domain`  `url` 
action\_result\.summary\.registrar\_name | string | 
action\_result\.summary\.admin\_email | string |  `email` 
action\_result\.summary\.created\_date | string | 
action\_result\.summary\.expires\_date | string | 
action\_result\.summary\.registrant\_name | string | 
action\_result\.summary\.registrant\_organization | string | 
action\_result\.summary\.registrant\_country | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.xforce\_whois\.expiresDate | string | 
action\_result\.data\.\*\.xforce\_whois\.contactEmail | string |  `email` 
action\_result\.data\.\*\.xforce\_whois\.registrarName | string | 
action\_result\.data\.\*\.xforce\_whois\.updatedDate | string | 
action\_result\.data\.\*\.xforce\_whois\.createdDate | string | 
action\_result\.data\.\*\.xforce\_whois\.contact\.\*\.organization | string | 
action\_result\.data\.\*\.xforce\_whois\.contact\.\*\.type | string | 
action\_result\.data\.\*\.xforce\_whois\.contact\.\*\.name | string | 
action\_result\.data\.\*\.xforce\_whois\.contact\.\*\.country | string |   

## action: 'whois ip'
Returns WHOIS report

Type: **investigate**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query\_value** |  required  | IP to Investigate | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.query\_value | string |  `ip` 
action\_result\.summary\.registrar\_name | string | 
action\_result\.summary\.admin\_email | string |  `email` 
action\_result\.summary\.created\_date | string | 
action\_result\.summary\.expires\_date | string | 
action\_result\.summary\.registrant\_name | string | 
action\_result\.summary\.registrant\_organization | string | 
action\_result\.summary\.registrant\_country | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.xforce\_whois\.expiresDate | string | 
action\_result\.data\.\*\.xforce\_whois\.contactEmail | string |  `email` 
action\_result\.data\.\*\.xforce\_whois\.registrarName | string | 
action\_result\.data\.\*\.xforce\_whois\.updatedDate | string | 
action\_result\.data\.\*\.xforce\_whois\.createdDate | string | 
action\_result\.data\.\*\.xforce\_whois\.contact\.\*\.organization | string | 
action\_result\.data\.\*\.xforce\_whois\.contact\.\*\.type | string | 
action\_result\.data\.\*\.xforce\_whois\.contact\.\*\.name | string | 
action\_result\.data\.\*\.xforce\_whois\.contact\.\*\.country | string |   

## action: 'url reputation'
Returns URL reputation report

Type: **investigate**  
Read only: **False**

Runs the X\-Force URL Report, URL Malware Report, and DNS Lookup\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query\_value** |  required  | URL to Investigate | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.query\_value | string |  `url` 
action\_result\.summary\.score | string | 
action\_result\.summary\.category | string | 
action\_result\.summary\.malware\_observed | numeric | 
action\_result\.summary\.malware\_last\_90 | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.xforce\_url\_report\.result\.score | numeric | 
action\_result\.data\.\*\.xforce\_url\_report\.result\.url | string |  `url` 
action\_result\.data\.\*\.xforce\_url\_report\.result\.categoryDescriptions\.\*\.category | string | 
action\_result\.data\.\*\.xforce\_url\_report\.result\.categoryDescriptions\.\*\.description | string | 
action\_result\.data\.\*\.xforce\_url\_report\.result\.cats\.\*\.category | string | 
action\_result\.data\.\*\.xforce\_url\_report\.result\.cats\.\*\.percentage | string | 
action\_result\.data\.\*\.xforce\_url\_report\.result\.score | numeric | 
action\_result\.data\.\*\.xforce\_url\_report\.associated\.\*\.url | string |  `url` 
action\_result\.data\.\*\.xforce\_url\_report\.associated\.\*\.categoryDescriptions\.\*\.category | string | 
action\_result\.data\.\*\.xforce\_url\_report\.associated\.\*\.categoryDescriptions\.\*\.description | string | 
action\_result\.data\.\*\.xforce\_url\_report\.associated\.cats\.\*\.category | string | 
action\_result\.data\.\*\.xforce\_url\_report\.associated\.cats\.\*\.percentage | string | 
action\_result\.data\.\*\.xforce\_url\_malware\.malware\.\*\.type | string | 
action\_result\.data\.\*\.xforce\_url\_malware\.malware\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.xforce\_url\_malware\.malware\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.xforce\_url\_malware\.malware\.\*\.firstseen | string | 
action\_result\.data\.\*\.xforce\_url\_malware\.malware\.\*\.lastseen | string | 
action\_result\.data\.\*\.xforce\_url\_malware\.malware\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.xforce\_url\_malware\.malware\.\*\.count | numeric | 
action\_result\.data\.\*\.xforce\_url\_malware\.malware\.\*\.filepath | string |  `file path` 
action\_result\.data\.\*\.xforce\_url\_malware\.malware\.\*\.origin | string | 
action\_result\.data\.\*\.xforce\_url\_malware\.malware\.\*\.family\.\*\.name | string | 
action\_result\.data\.\*\.xforce\_dns\.A\.\*\.record | string |  `ip` 
action\_result\.data\.\*\.xforce\_dns\.AAAA\.\*\.record | string |  `ip` 
action\_result\.data\.\*\.xforce\_dns\.TXT\.\*\.\*\.record | string | 
action\_result\.data\.\*\.xforce\_dns\.MX\.\*\.exchange | string | 
action\_result\.data\.\*\.xforce\_dns\.MX\.\*\.priority | string | 
action\_result\.data\.\*\.xforce\_dns\.total\_rows | numeric | 
action\_result\.data\.\*\.xforce\_dns\.Passive\.query | string | 
action\_result\.data\.\*\.xforce\_dns\.Passive\.records\.\*\.value | string | 
action\_result\.data\.\*\.xforce\_dns\.Passive\.records\.\*\.type | string | 
action\_result\.data\.\*\.xforce\_dns\.Passive\.records\.\*\.recordType | string | 
action\_result\.data\.\*\.xforce\_dns\.Passive\.records\.\*\.first | string | 
action\_result\.data\.\*\.xforce\_dns\.Passive\.records\.\*\.last | string |   

## action: 'file reputation'
Returns malware report for a given hash

Type: **investigate**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | File Hash to Investigate | string |  `hash`  `sha256`  `sha1`  `md5` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.hash | string |  `hash`  `sha256`  `sha1`  `md5` 
action\_result\.summary\.risk | string | 
action\_result\.summary\.cnc\_servers | numeric | 
action\_result\.summary\.email\_sources | numeric | 
action\_result\.summary\.email\_subjects | numeric | 
action\_result\.summary\.download\_sources | numeric | 
action\_result\.summary\.family | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.type | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.md5 | string |  `md5` 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.hash | string |  `hash` 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.created | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.risk | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.mimetype | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.family\.\*\.name | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.familyMembers\.\*\.name | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.familyMembers\.\*\.count | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.CnCServers\.count | numeric | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.CnCServers\.rows\.\*\.count | numeric | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.CnCServers\.rows\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.CnCServers\.rows\.\*\.filepath | string |  `file path` 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.CnCServers\.rows\.\*\.firstseen | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.CnCServers\.rows\.\*\.host | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.CnCServers\.rows\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.CnCServers\.rows\.\*\.lastseen | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.CnCServers\.rows\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.CnCServers\.rows\.\*\.origin | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.CnCServers\.rows\.\*\.schema | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.CnCServers\.rows\.\*\.type | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.CnCServers\.rows\.\*\.uri | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.downloadServers\.rows\.\*\.count | numeric | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.downloadServers\.rows\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.downloadServers\.rows\.\*\.filepath | string |  `file path` 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.downloadServers\.rows\.\*\.firstseen | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.downloadServers\.rows\.\*\.host | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.downloadServers\.rows\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.downloadServers\.rows\.\*\.lastseen | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.downloadServers\.rows\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.downloadServers\.rows\.\*\.origin | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.downloadServers\.rows\.\*\.schema | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.downloadServers\.rows\.\*\.type | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.downloadServers\.rows\.\*\.uri | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.emails\.count | numeric | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.emails\.rows\.\*\.count | numeric | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.emails\.rows\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.emails\.rows\.\*\.filepath | string |  `file path` 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.emails\.rows\.\*\.firstseen | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.emails\.rows\.\*\.host | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.emails\.rows\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.emails\.rows\.\*\.lastseen | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.emails\.rows\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.emails\.rows\.\*\.origin | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.emails\.rows\.\*\.schema | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.emails\.rows\.\*\.type | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.emails\.rows\.\*\.uri | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.external\.detectionCoverage | numeric | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.external\.family\.\*\.name | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.subjects\.rows\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.subjects\.count | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.subjects\.rows\.\*\.subject | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.subjects\.rows\.\*\.count | numeric | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.subjects\.rows\.\*\.firstseen | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.subjects\.rows\.\*\.ips\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.subjects\.rows\.\*\.lastseen | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.subjects\.rows\.\*\.origin | string | 
action\_result\.data\.\*\.xforce\_malware\_report\.malware\.origins\.subjects\.rows\.\*\.type | string |   

## action: 'test connectivity'
Validates connectivity to XForce

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output