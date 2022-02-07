[comment]: # "Auto-generated SOAR connector documentation"
# FireAMP

Publisher: Splunk  
Connector Version: 2\.1\.11  
Product Vendor: Cisco Systems  
Product Name: FireAMP  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

This App allows for querying endpoints connected to Cisco FireAMP while also providing investigative hunting capabilities

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
#### To Generate API Credentials

-   Go to Accounts \>\> API Credentials
-   Click New API Credential to generate an API key for your application. You can enter the name of
    the application for reference purposes and assign a scope of read only or read and write
    permissions as per your requirements.
-   Store this generated API key somewhere secure since it cannot be retrieved after closing the
    window.

#### Base URL

-   There are 3 different Base URLs available:

      

    -   api.amp.cisco.com
    -   api.apjc.amp.cisco.com
    -   api.eu.amp.cisco.com

-   To find the Base URL, Go to Accounts \>\> API Credentials

-   Click on **View API Documentation** . It will redirect to the Endpoints API page. Check the
    value of the **api_host** parameter in the URL.

-   If Base URL is not provided, **https://api.amp.sourcefire.com/** will be used as the Base URL by
    default.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a FireAMP asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  optional  | string | Base URL
**api\_client\_id** |  required  | string | API Client ID
**api\_key** |  required  | password | API Key

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration by attempting to connect and getting the version of the API endpoint  
[list endpoints](#action-list-endpoints) - List all of the endpoints connected to FireAMP  
[hunt file](#action-hunt-file) - Search for a file matching a SHA256 hash across all endpoints  
[hunt ip](#action-hunt-ip) - Search for a given IP  
[hunt url](#action-hunt-url) - Search for a given URL  
[list groups](#action-list-groups) - List all of the groups are present in FireAMP  
[list policies](#action-list-policies) - List all of the policies present in FireAMP  
[change policy](#action-change-policy) - Updates group to given windows policy  
[change group](#action-change-group) - Change the group of provided GUID endpoint  
[unquarantine device](#action-unquarantine-device) - Stop host isolation based on connector GUID  
[quarantine device](#action-quarantine-device) - Isolate host based on connector GUID  
[find device](#action-find-device) - Finds system with search parameters  
[get device info](#action-get-device-info) - Get information about a device, given its connector GUID  
[block hash](#action-block-hash) - Add a file hash \(sha256 only\) to a file list specified by GUID  
[unblock hash](#action-unblock-hash) - Remove a file hash \(sha256 only\) from a file list specified by GUID  
[allow hash](#action-allow-hash) - Add a file hash \(sha256 only\) to a file list specified by GUID  
[disallow hash](#action-disallow-hash) - Remove all sha256 file hashes from a file list specified by GUID  
[list filelists](#action-list-filelists) - List all of the File Lists \(application blocking & simple custom detections\) in FireAMP  
[get filelist](#action-get-filelist) - Get all of the hashes in a File List in FireAMP\. Lists can be retrieved by UUID, or file list name and type  
[remove listitem](#action-remove-listitem) - Removes file hash from file list  
[add listitem](#action-add-listitem) - Add file hash as listitem to file list  
[find listitem](#action-find-listitem) - Finds file hash in specified file list  
[get device trajectory](#action-get-device-trajectory) - Retrieve trajectory info about a device  
[get device events](#action-get-device-events) - Retrieve device events  

## action: 'test connectivity'
Validate the asset configuration by attempting to connect and getting the version of the API endpoint

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list endpoints'
List all of the endpoints connected to FireAMP

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.data\.\*\.active | boolean | 
action\_result\.data\.\*\.data\.\*\.connector\_guid | string |  `fireamp connector guid` 
action\_result\.data\.\*\.data\.\*\.connector\_version | string | 
action\_result\.data\.\*\.data\.\*\.demo | boolean | 
action\_result\.data\.\*\.data\.\*\.external\_ip | string |  `ip` 
action\_result\.data\.\*\.data\.\*\.group\_guid | string | 
action\_result\.data\.\*\.data\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.data\.\*\.install\_date | string | 
action\_result\.data\.\*\.data\.\*\.internal\_ips | string |  `ip` 
action\_result\.data\.\*\.data\.\*\.is\_compromised | boolean | 
action\_result\.data\.\*\.data\.\*\.isolation\.available | boolean | 
action\_result\.data\.\*\.data\.\*\.isolation\.status | string | 
action\_result\.data\.\*\.data\.\*\.last\_seen | string | 
action\_result\.data\.\*\.data\.\*\.links\.computer | string | 
action\_result\.data\.\*\.data\.\*\.links\.group | string |  `url` 
action\_result\.data\.\*\.data\.\*\.links\.trajectory | string | 
action\_result\.data\.\*\.data\.\*\.network\_addresses\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.data\.\*\.network\_addresses\.\*\.mac | string |  `mac address` 
action\_result\.data\.\*\.data\.\*\.operating\_system | string | 
action\_result\.data\.\*\.data\.\*\.orbital\.status | string | 
action\_result\.data\.\*\.data\.\*\.policy\.guid | string | 
action\_result\.data\.\*\.data\.\*\.policy\.name | string | 
action\_result\.data\.\*\.data\.\*\.windows\_processor\_id | string | 
action\_result\.data\.\*\.metadata\.links\.self | string | 
action\_result\.data\.\*\.metadata\.results\.current\_item\_count | numeric | 
action\_result\.data\.\*\.metadata\.results\.index | numeric | 
action\_result\.data\.\*\.metadata\.results\.items\_per\_page | numeric | 
action\_result\.data\.\*\.metadata\.results\.total | numeric | 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.total\_endpoints | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt file'
Search for a file matching a SHA256 hash across all endpoints

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | SHA256 of file to hunt | string |  `hash`  `sha256` 
**check\_execution** |  optional  | Check file execution | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.check\_execution | boolean | 
action\_result\.parameter\.hash | string |  `hash`  `sha256` 
action\_result\.data\.\*\.data\.\*\.active | boolean | 
action\_result\.data\.\*\.data\.\*\.connector\_guid | string |  `fireamp connector guid` 
action\_result\.data\.\*\.data\.\*\.file\_execution\_details\.executed | boolean | 
action\_result\.data\.\*\.data\.\*\.file\_execution\_details\.file\_name | string |  `file path` 
action\_result\.data\.\*\.data\.\*\.file\_execution\_details\.file\_path | string |  `file name` 
action\_result\.data\.\*\.data\.\*\.file\_execution\_details\.message | string | 
action\_result\.data\.\*\.data\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.data\.\*\.links\.computer | string |  `url` 
action\_result\.data\.\*\.data\.\*\.links\.group | string |  `url` 
action\_result\.data\.\*\.data\.\*\.links\.trajectory | string | 
action\_result\.data\.\*\.data\.\*\.windows\_processor\_id | string | 
action\_result\.data\.\*\.metadata\.links\.self | string |  `url` 
action\_result\.data\.\*\.metadata\.results\.current\_item\_count | numeric | 
action\_result\.data\.\*\.metadata\.results\.index | numeric | 
action\_result\.data\.\*\.metadata\.results\.items\_per\_page | numeric | 
action\_result\.data\.\*\.metadata\.results\.total | numeric | 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.device\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt ip'
Search for a given IP

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP Address to hunt | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data\.\*\.data\.\*\.active | boolean | 
action\_result\.data\.\*\.data\.\*\.connector\_guid | string |  `fireamp connector guid` 
action\_result\.data\.\*\.data\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.data\.\*\.links\.computer | string |  `url` 
action\_result\.data\.\*\.data\.\*\.links\.group | string |  `url` 
action\_result\.data\.\*\.data\.\*\.links\.trajectory | string |  `url` 
action\_result\.data\.\*\.data\.\*\.windows\_processor\_id | string | 
action\_result\.data\.\*\.metadata\.links\.self | string |  `url` 
action\_result\.data\.\*\.metadata\.results\.current\_item\_count | numeric | 
action\_result\.data\.\*\.metadata\.results\.index | numeric | 
action\_result\.data\.\*\.metadata\.results\.items\_per\_page | numeric | 
action\_result\.data\.\*\.metadata\.results\.total | numeric | 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.device\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt url'
Search for a given URL

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to hunt | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.data\.\*\.data\.\*\.active | boolean | 
action\_result\.data\.\*\.data\.\*\.connector\_guid | string |  `fireamp connector guid` 
action\_result\.data\.\*\.data\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.data\.\*\.links\.computer | string |  `url` 
action\_result\.data\.\*\.data\.\*\.links\.group | string |  `url` 
action\_result\.data\.\*\.data\.\*\.links\.trajectory | string |  `url` 
action\_result\.data\.\*\.metadata\.links\.self | string |  `url` 
action\_result\.data\.\*\.metadata\.results\.current\_item\_count | numeric | 
action\_result\.data\.\*\.metadata\.results\.index | numeric | 
action\_result\.data\.\*\.metadata\.results\.items\_per\_page | numeric | 
action\_result\.data\.\*\.metadata\.results\.total | numeric | 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.device\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list groups'
List all of the groups are present in FireAMP

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.data\.\*\.description | string | 
action\_result\.data\.\*\.data\.\*\.guid | string | 
action\_result\.data\.\*\.data\.\*\.links\.group | string |  `url` 
action\_result\.data\.\*\.data\.\*\.name | string | 
action\_result\.data\.\*\.data\.\*\.source | string | 
action\_result\.data\.\*\.metadata\.links\.self | string |  `url` 
action\_result\.data\.\*\.metadata\.results\.current\_item\_count | numeric | 
action\_result\.data\.\*\.metadata\.results\.index | numeric | 
action\_result\.data\.\*\.metadata\.results\.items\_per\_page | numeric | 
action\_result\.data\.\*\.metadata\.results\.total | numeric | 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.group\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list policies'
List all of the policies present in FireAMP

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  optional  | Policy Name Filter | string | 
**product** |  optional  | Product Name Filter | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.name | string | 
action\_result\.parameter\.product | string | 
action\_result\.data\.\*\.data\.\*\.default | boolean | 
action\_result\.data\.\*\.data\.\*\.description | string | 
action\_result\.data\.\*\.data\.\*\.guid | string | 
action\_result\.data\.\*\.data\.\*\.links\.policy | string |  `url` 
action\_result\.data\.\*\.data\.\*\.name | string | 
action\_result\.data\.\*\.data\.\*\.product | string | 
action\_result\.data\.\*\.data\.\*\.serial\_number | numeric | 
action\_result\.data\.\*\.data\.install\_date | string |  `url` 
action\_result\.data\.\*\.metadata\.links\.next | string |  `url` 
action\_result\.data\.\*\.metadata\.links\.prev | string |  `url` 
action\_result\.data\.\*\.metadata\.links\.self | string | 
action\_result\.data\.\*\.metadata\.results\.current\_item\_count | numeric | 
action\_result\.data\.\*\.metadata\.results\.index | numeric | 
action\_result\.data\.\*\.metadata\.results\.items\_per\_page | numeric | 
action\_result\.data\.\*\.metadata\.results\.total | numeric | 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.policy\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'change policy'
Updates group to given windows policy

Type: **contain**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**policy\_guid** |  optional  | Windows policy GUID | string | 
**policy\_name** |  optional  | Windows policy name | string | 
**group\_guid** |  optional  | Group GUID | string | 
**group\_name** |  optional  | Group name | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.group\_guid | string | 
action\_result\.parameter\.group\_name | string | 
action\_result\.parameter\.policy\_guid | string | 
action\_result\.parameter\.policy\_name | string | 
action\_result\.data\.\*\.policy\_changed | boolean | 
action\_result\.data\.\*\.policy\_guid | string | 
action\_result\.summary\.policy\_changed | boolean | 
action\_result\.summary\.policy\_guid | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'change group'
Change the group of provided GUID endpoint

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**connector\_guid** |  required  | Connector GUID on endpoint | string |  `fireamp connector guid` 
**group\_guid** |  optional  | Group GUID | string | 
**group\_name** |  optional  | Group name | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.connector\_guid | string |  `fireamp connector guid` 
action\_result\.parameter\.group\_guid | string | 
action\_result\.parameter\.group\_name | string | 
action\_result\.data\.\*\.group\_changed | boolean | 
action\_result\.data\.\*\.group\_guid | string | 
action\_result\.summary\.group\_changed | boolean | 
action\_result\.summary\.group\_guid | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unquarantine device'
Stop host isolation based on connector GUID

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**connector\_guid** |  required  | Connector GUID on endpoint | string |  `fireamp connector guid` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.connector\_guid | string |  `fireamp connector guid` 
action\_result\.data | string | 
action\_result\.data\.\*\.data\.available | boolean | 
action\_result\.data\.\*\.data\.comment | string | 
action\_result\.data\.\*\.version | string | 
action\_result\.data\.\*\.data\.isolated\_by | string | 
action\_result\.data\.\*\.data\.status | string | 
action\_result\.data\.\*\.data\.unlock\_code | string | 
action\_result\.data\.\*\.metadata\.links\.self | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'quarantine device'
Isolate host based on connector GUID

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**connector\_guid** |  required  | Connector GUID on endpoint | string |  `fireamp connector guid` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.connector\_guid | string |  `fireamp connector guid` 
action\_result\.data | string | 
action\_result\.data\.\*\.data\.available | string | 
action\_result\.data\.\*\.data\.comment | string | 
action\_result\.data\.\*\.data\.isolated\_by | string | 
action\_result\.data\.\*\.version | string | 
action\_result\.data\.\*\.data\.status | string | 
action\_result\.data\.\*\.data\.unlock\_code | string | 
action\_result\.data\.\*\.metadata\.links\.self | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'find device'
Finds system with search parameters

Type: **investigate**  
Read only: **True**

If finding by user, no other search options can be used\. Additionally group name and group GUID are mutually exclusive search options\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group\_guid** |  optional  | Group GUID | string | 
**group\_name** |  optional  | Group name | string | 
**user** |  optional  | User | string | 
**hostname** |  optional  | Hostname | string | 
**external\_ip** |  optional  | External ip | string |  `ip` 
**internal\_ip** |  optional  | Internal ip | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.external\_ip | string |  `ip` 
action\_result\.parameter\.group\_guid | string | 
action\_result\.parameter\.group\_name | string | 
action\_result\.parameter\.hostname | string | 
action\_result\.parameter\.internal\_ip | string |  `ip` 
action\_result\.parameter\.user | string | 
action\_result\.data\.\*\.data\.\*\.active | boolean | 
action\_result\.data\.\*\.data\.\*\.connector\_guid | string |  `fireamp connector guid` 
action\_result\.data\.\*\.data\.\*\.connector\_version | string | 
action\_result\.data\.\*\.data\.\*\.demo | boolean | 
action\_result\.data\.\*\.data\.\*\.external\_ip | string |  `ip` 
action\_result\.data\.\*\.data\.\*\.group\_guid | string | 
action\_result\.data\.\*\.data\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.data\.\*\.install\_date | string | 
action\_result\.data\.\*\.data\.\*\.internal\_ips | string |  `ip` 
action\_result\.data\.\*\.data\.\*\.is\_compromised | boolean | 
action\_result\.data\.\*\.data\.\*\.isolation\.available | boolean | 
action\_result\.data\.\*\.data\.\*\.isolation\.status | string | 
action\_result\.data\.\*\.data\.\*\.last\_seen | string | 
action\_result\.data\.\*\.data\.\*\.links\.computer | string |  `url` 
action\_result\.data\.\*\.data\.\*\.links\.group | string |  `url` 
action\_result\.data\.\*\.data\.\*\.links\.trajectory | string |  `url` 
action\_result\.data\.\*\.data\.\*\.network\_addresses\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.data\.\*\.network\_addresses\.\*\.mac | string |  `mac address` 
action\_result\.data\.\*\.data\.\*\.operating\_system | string | 
action\_result\.data\.\*\.data\.\*\.orbital\.status | string | 
action\_result\.data\.\*\.data\.\*\.policy\.guid | string | 
action\_result\.data\.\*\.data\.\*\.policy\.name | string | 
action\_result\.data\.\*\.data\.\*\.windows\_processor\_id | string | 
action\_result\.data\.\*\.data\.demo | boolean | 
action\_result\.data\.\*\.data\.install\_date | string | 
action\_result\.data\.\*\.data\.is\_compromised | boolean | 
action\_result\.data\.\*\.data\.isolation\.available | boolean | 
action\_result\.data\.\*\.data\.isolation\.status | string | 
action\_result\.data\.\*\.data\.last\_seen | string | 
action\_result\.data\.\*\.data\.orbital\.status | string | 
action\_result\.data\.\*\.data\.windows\_processor\_id | string | 
action\_result\.data\.\*\.links\.self | string | 
action\_result\.data\.\*\.metadata\.links\.self | string |  `url` 
action\_result\.data\.\*\.metadata\.results\.current\_item\_count | numeric | 
action\_result\.data\.\*\.metadata\.results\.index | numeric | 
action\_result\.data\.\*\.metadata\.results\.items\_per\_page | numeric | 
action\_result\.data\.\*\.metadata\.results\.total | numeric | 
action\_result\.data\.\*\.results\.current\_item\_count | numeric | 
action\_result\.data\.\*\.results\.index | numeric | 
action\_result\.data\.\*\.results\.items\_per\_page | numeric | 
action\_result\.data\.\*\.results\.total | numeric | 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.total\_endpoints | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get device info'
Get information about a device, given its connector GUID

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**connector\_guid** |  required  | Connector GUID on endpoint | string |  `fireamp connector guid` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.connector\_guid | string |  `fireamp connector guid` 
action\_result\.data\.\*\.data\.active | boolean | 
action\_result\.data\.\*\.data\.connector\_guid | string |  `fireamp connector guid` 
action\_result\.data\.\*\.data\.connector\_version | string | 
action\_result\.data\.\*\.data\.external\_ip | string |  `ip` 
action\_result\.data\.\*\.data\.group\_guid | string | 
action\_result\.data\.\*\.data\.hostname | string |  `host name` 
action\_result\.data\.\*\.data\.internal\_ips | string |  `ip` 
action\_result\.data\.\*\.data\.links\.computer | string |  `url` 
action\_result\.data\.\*\.data\.demo | boolean | 
action\_result\.data\.\*\.data\.orbital\.status | string | 
action\_result\.data\.\*\.data\.isolation\.status | string | 
action\_result\.data\.\*\.data\.isolation\.available | boolean | 
action\_result\.data\.\*\.data\.last\_seen | string | 
action\_result\.data\.\*\.data\.install\_date | string | 
action\_result\.data\.\*\.data\.is\_compromised | boolean | 
action\_result\.data\.\*\.data\.windows\_processor\_id | string | 
action\_result\.data\.\*\.data\.links\.group | string |  `url` 
action\_result\.data\.\*\.data\.links\.trajectory | string |  `url` 
action\_result\.data\.\*\.data\.network\_addresses\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.data\.network\_addresses\.\*\.mac | string |  `mac address` 
action\_result\.data\.\*\.data\.operating\_system | string | 
action\_result\.data\.\*\.data\.policy\.guid | string | 
action\_result\.data\.\*\.data\.policy\.name | string | 
action\_result\.data\.\*\.metadata\.links\.self | string |  `url` 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.total\_endpoints | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'block hash'
Add a file hash \(sha256 only\) to a file list specified by GUID

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file\_list\_guid** |  required  | File List GUID on FireAMP | string |  `fireamp file list guid` 
**hash** |  required  | SHA256 of file to add to file list | string |  `hash`  `sha256` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_list\_guid | string |  `fireamp file list guid` 
action\_result\.parameter\.hash | string |  `hash`  `sha256` 
action\_result\.data\.\*\.data\.description | string | 
action\_result\.data\.\*\.data\.links\.file\_list | string |  `url` 
action\_result\.data\.\*\.data\.sha256 | string |  `hash`  `sha256` 
action\_result\.data\.\*\.data\.source | string | 
action\_result\.data\.\*\.metadata\.links\.self | string |  `url` 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.file\_added\_to\_list | boolean | 
action\_result\.summary\.file\_hash\_added | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unblock hash'
Remove a file hash \(sha256 only\) from a file list specified by GUID

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file\_list\_guid** |  required  | File List GUID on FireAMP | string |  `fireamp file list guid` 
**hash** |  required  | SHA256 of file to remove from file list | string |  `hash`  `sha256` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_list\_guid | string |  `fireamp file list guid` 
action\_result\.parameter\.hash | string |  `hash`  `sha256` 
action\_result\.data\.\*\.data\.description | string | 
action\_result\.data\.\*\.metadata\.links\.self | string |  `url` 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.file\_removed\_from\_list | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'allow hash'
Add a file hash \(sha256 only\) to a file list specified by GUID

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file\_list\_guid** |  required  | File List GUID on FireAMP | string |  `fireamp file list guid` 
**hash** |  required  | SHA256 of file to add to file list | string |  `hash`  `sha256` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_list\_guid | string |  `fireamp file list guid` 
action\_result\.parameter\.hash | string |  `hash`  `sha256` 
action\_result\.data\.\*\.data\.description | string | 
action\_result\.data\.\*\.data\.links\.file\_list | string |  `url` 
action\_result\.data\.\*\.data\.sha256 | string |  `hash`  `sha256` 
action\_result\.data\.\*\.data\.source | string | 
action\_result\.data\.\*\.metadata\.links\.self | string |  `url` 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.file\_added\_to\_list | boolean | 
action\_result\.summary\.file\_hash\_added | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'disallow hash'
Remove all sha256 file hashes from a file list specified by GUID

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file\_list\_guid** |  required  | File List GUID on FireAMP | string |  `fireamp file list guid` 
**hash** |  required  | SHA256 of file to remove from file list | string |  `hash`  `sha256` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_list\_guid | string |  `fireamp file list guid` 
action\_result\.parameter\.hash | string |  `hash`  `sha256` 
action\_result\.data\.\*\.data\.description | string | 
action\_result\.data\.\*\.metadata\.links\.self | string |  `url` 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.file\_removed\_from\_list | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list filelists'
List all of the File Lists \(application blocking & simple custom detections\) in FireAMP

Type: **generic**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.guid | string |  `fireamp file list guid` 
action\_result\.data\.\*\.links\.file\_list | string |  `url` 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.total\_lists | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get filelist'
Get all of the hashes in a File List in FireAMP\. Lists can be retrieved by UUID, or file list name and type

Type: **generic**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file\_list\_guid** |  optional  | File List GUID on FireAMP | string |  `fireamp file list guid` 
**name** |  optional  | File list name | string | 
**type** |  optional  | File list type | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_list\_guid | string |  `fireamp file list guid` 
action\_result\.parameter\.name | string | 
action\_result\.parameter\.type | string | 
action\_result\.data\.\*\.data\.guid | string |  `fireamp file list guid` 
action\_result\.data\.\*\.data\.items\.\*\.description | string | 
action\_result\.data\.\*\.data\.items\.\*\.links\.file\_list | string |  `url` 
action\_result\.data\.\*\.data\.items\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.data\.name | string | 
action\_result\.data\.\*\.data\.policies\.\*\.guid | string | 
action\_result\.data\.\*\.data\.policies\.\*\.links\.policy | string |  `url` 
action\_result\.data\.\*\.data\.policies\.\*\.name | string | 
action\_result\.data\.\*\.metadata\.links\.self | string |  `url` 
action\_result\.data\.\*\.metadata\.results\.current\_item\_count | numeric | 
action\_result\.data\.\*\.metadata\.results\.index | numeric | 
action\_result\.data\.\*\.metadata\.results\.items\_per\_page | numeric | 
action\_result\.data\.\*\.metadata\.results\.total | numeric | 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.file\_count | numeric | 
action\_result\.summary\.file\_list\_guid | string | 
action\_result\.summary\.file\_list\_name | string | 
action\_result\.summary\.total\_endpoints | numeric | 
action\_result\.summary\.total\_hashes | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'remove listitem'
Removes file hash from file list

Type: **correct**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | File hash \(sha256\) | string |  `sha256` 
**file\_list\_guid** |  optional  | File List GUID on FireAMP | string |  `fireamp file list guid` 
**name** |  optional  | File list name | string | 
**type** |  optional  | File list type | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_list\_guid | string |  `fireamp file list guid` 
action\_result\.parameter\.hash | string |  `sha256` 
action\_result\.parameter\.name | string | 
action\_result\.parameter\.type | string | 
action\_result\.data\.\*\.file\_deleted | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.summary\.file\_deleted | boolean |   

## action: 'add listitem'
Add file hash as listitem to file list

Type: **correct**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | File hash \(sha256\) | string |  `sha256` 
**file\_list\_guid** |  optional  | File List GUID on FireAMP | string |  `fireamp file list guid` 
**name** |  optional  | File list name | string | 
**type** |  optional  | File list type | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_list\_guid | string |  `fireamp file list guid` 
action\_result\.parameter\.hash | string |  `sha256` 
action\_result\.parameter\.name | string | 
action\_result\.parameter\.type | string | 
action\_result\.data\.\*\.data\.links\.file\_list | string | 
action\_result\.data\.\*\.data\.sha256 | string | 
action\_result\.data\.\*\.data\.source | string | 
action\_result\.data\.\*\.file\_added | boolean | 
action\_result\.data\.\*\.metadata\.links\.self | string | 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.file\_added | boolean | 
action\_result\.summary\.file\_deleted | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'find listitem'
Finds file hash in specified file list

Type: **generic**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | File hash \(sha256\) | string |  `sha256` 
**file\_list\_guid** |  optional  | File List GUID on FireAMP | string |  `fireamp file list guid` 
**name** |  optional  | File list name to find the file list GUID | string | 
**type** |  optional  | File list type to find the file list GUID | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_list\_guid | string |  `fireamp file list guid` 
action\_result\.parameter\.hash | string |  `sha256` 
action\_result\.parameter\.name | string | 
action\_result\.parameter\.type | string | 
action\_result\.data\.\*\.data\.description | string | 
action\_result\.data\.\*\.data\.guid | string |  `fireamp file list guid` 
action\_result\.data\.\*\.data\.links\.file\_list | string |  `url` 
action\_result\.data\.\*\.data\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.data\.source | string | 
action\_result\.data\.\*\.metadata\.links\.self | string |  `url` 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.file\_found | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get device trajectory'
Retrieve trajectory info about a device

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**connector\_guid** |  required  | Connector GUID on endpoint | string |  `fireamp connector guid` 
**filter** |  optional  | Filter trajectory info | string |  `sha256`  `url`  `ip` 
**days\_back** |  optional  | Return events from a number of days back | numeric | 
**executed\_only** |  optional  | Only retrieve events where the file has been executed | boolean | 
**limit** |  optional  | Limit number of results | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.connector\_guid | string |  `fireamp connector guid` 
action\_result\.parameter\.days\_back | numeric | 
action\_result\.parameter\.executed\_only | boolean | 
action\_result\.parameter\.filter | string |  `sha256`  `url`  `ip` 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.computer\.active | boolean | 
action\_result\.data\.\*\.computer\.connector\_guid | string | 
action\_result\.data\.\*\.computer\.connector\_version | string | 
action\_result\.data\.\*\.computer\.demo | boolean | 
action\_result\.data\.\*\.computer\.external\_ip | string |  `ip` 
action\_result\.data\.\*\.computer\.group\_guid | string | 
action\_result\.data\.\*\.computer\.hostname | string |  `host name` 
action\_result\.data\.\*\.computer\.install\_date | string | 
action\_result\.data\.\*\.computer\.internal\_ips | string | 
action\_result\.data\.\*\.computer\.is\_compromised | boolean | 
action\_result\.data\.\*\.computer\.isolation\.available | boolean | 
action\_result\.data\.\*\.computer\.isolation\.status | string | 
action\_result\.data\.\*\.computer\.links\.computer | string |  `url` 
action\_result\.data\.\*\.computer\.links\.group | string |  `url` 
action\_result\.data\.\*\.computer\.links\.trajectory | string |  `url` 
action\_result\.data\.\*\.computer\.network\_addresses\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.computer\.network\_addresses\.\*\.mac | string | 
action\_result\.data\.\*\.computer\.operating\_system | string | 
action\_result\.data\.\*\.computer\.orbital\.status | string | 
action\_result\.data\.\*\.computer\.policy\.guid | string | 
action\_result\.data\.\*\.computer\.policy\.name | string | 
action\_result\.data\.\*\.computer\.windows\_processor\_id | string | 
action\_result\.data\.\*\.events\.\*\.file\.parent\.identity\.md5 | string | 
action\_result\.data\.\*\.events\.\*\.file\.parent\.identity\.sha1 | string | 
action\_result\.data\.\*\.events\.\*\.file\.parent\.file\_name | string | 
action\_result\.data\.\*\.events\.\*\.file\.parent\.process\_id | numeric | 
action\_result\.data\.\*\.events\.\*\.scan\.clean | boolean | 
action\_result\.data\.\*\.events\.\*\.scan\.description | string | 
action\_result\.data\.\*\.events\.\*\.scan\.scanned\_files | numeric | 
action\_result\.data\.\*\.events\.\*\.scan\.scanned\_paths | numeric | 
action\_result\.data\.\*\.events\.\*\.scan\.scanned\_processes | numeric | 
action\_result\.data\.\*\.events\.\*\.scan\.malicious\_detections | numeric | 
action\_result\.data\.\*\.data\.description | string | 
action\_result\.data\.\*\.data\.guid | string |  `fireamp file list guid` 
action\_result\.data\.\*\.data\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.data\.source | string | 
action\_result\.data\.\*\.events\.\*\.cloud\_ioc\.description | string | 
action\_result\.data\.\*\.events\.\*\.cloud\_ioc\.short\_description | string | 
action\_result\.data\.\*\.events\.\*\.command\_line\.arguments | string | 
action\_result\.data\.\*\.events\.\*\.command\_line\.environment\.Path | string |  `file path` 
action\_result\.data\.\*\.events\.\*\.command\_line\.environment\.USERNAME | string |  `user name` 
action\_result\.data\.\*\.events\.\*\.date | string | 
action\_result\.data\.\*\.events\.\*\.detection | string | 
action\_result\.data\.\*\.events\.\*\.id | string | 
action\_result\.data\.\*\.events\.\*\.severity | string | 
action\_result\.data\.\*\.events\.\*\.detection\_id | string | 
action\_result\.data\.\*\.events\.\*\.event\_type | string | 
action\_result\.data\.\*\.data\.links\.file\_list | string |  `url` 
action\_result\.data\.\*\.events\.\*\.event\_type\_id | numeric | 
action\_result\.data\.\*\.events\.\*\.file\.disposition | string | 
action\_result\.data\.\*\.events\.\*\.file\.file\_name | string |  `file name`  `sha1` 
action\_result\.data\.\*\.events\.\*\.file\.file\_path | string |  `file name` 
action\_result\.data\.\*\.events\.\*\.file\.file\_type | string | 
action\_result\.data\.\*\.events\.\*\.file\.identity\.md5 | string | 
action\_result\.data\.\*\.events\.\*\.file\.identity\.sha1 | string | 
action\_result\.data\.\*\.events\.\*\.file\.identity\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.events\.\*\.file\.parent\.disposition | string | 
action\_result\.data\.\*\.events\.\*\.file\.parent\.identity\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.events\.\*\.group\_guids | string | 
action\_result\.data\.\*\.events\.\*\.isolation\.duration | numeric | 
action\_result\.data\.\*\.events\.\*\.network\_info\.dirty\_url | string |  `url` 
action\_result\.data\.\*\.events\.\*\.network\_info\.local\_ip | string |  `ip` 
action\_result\.data\.\*\.events\.\*\.network\_info\.local\_port | numeric | 
action\_result\.data\.\*\.events\.\*\.network\_info\.nfm\.direction | string | 
action\_result\.data\.\*\.events\.\*\.network\_info\.nfm\.protocol | string | 
action\_result\.data\.\*\.events\.\*\.network\_info\.parent\.disposition | string | 
action\_result\.data\.\*\.events\.\*\.network\_info\.parent\.identity\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.events\.\*\.network\_info\.remote\_ip | string |  `ip` 
action\_result\.data\.\*\.events\.\*\.network\_info\.remote\_port | numeric | 
action\_result\.data\.\*\.events\.\*\.start\_date | string | 
action\_result\.data\.\*\.events\.\*\.start\_timestamp | numeric | 
action\_result\.data\.\*\.events\.\*\.timestamp | numeric | 
action\_result\.data\.\*\.events\.\*\.timestamp\_nanoseconds | numeric | 
action\_result\.data\.\*\.events\.\*\.vulnerabilities\.\*\.cve | string | 
action\_result\.data\.\*\.events\.\*\.vulnerabilities\.\*\.name | string | 
action\_result\.data\.\*\.events\.\*\.vulnerabilities\.\*\.score | numeric | 
action\_result\.data\.\*\.events\.\*\.vulnerabilities\.\*\.url | string | 
action\_result\.data\.\*\.events\.\*\.vulnerabilities\.\*\.version | string | 
action\_result\.data\.\*\.metadata\.links\.self | string |  `url` 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.file\_found | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get device events'
Retrieve device events

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**connector\_guid** |  optional  | Connector GUID on endpoint | string |  `fireamp connector guid` 
**detection\_sha256** |  optional  | Filter by detection sha256 | string |  `hash` 
**application\_sha256** |  optional  | Filter by application sha256 | string |  `hash` 
**group\_guid** |  optional  | Filter by group GUID | string | 
**start\_date** |  optional  | Filter by event start date | string | 
**offset** |  optional  | Results offset | numeric | 
**event\_type** |  optional  | Filter by event type | string | 
**limit** |  optional  | Limit number of results returned | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.application\_sha256 | string |  `hash` 
action\_result\.parameter\.connector\_guid | string |  `fireamp connector guid` 
action\_result\.parameter\.detection\_sha256 | string |  `hash` 
action\_result\.parameter\.event\_type | string | 
action\_result\.parameter\.group\_guid | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.offset | numeric | 
action\_result\.parameter\.start\_date | string | 
action\_result\.data\.\*\.events\.\*\.cloud\_ioc\.description | string | 
action\_result\.data\.\*\.events\.\*\.cloud\_ioc\.short\_description | string | 
action\_result\.data\.\*\.events\.\*\.computer\.active | boolean | 
action\_result\.data\.\*\.events\.\*\.computer\.connector\_guid | string | 
action\_result\.data\.\*\.events\.\*\.computer\.external\_ip | string |  `ip` 
action\_result\.data\.\*\.events\.\*\.computer\.links\.computer | string |  `ip` 
action\_result\.data\.\*\.events\.\*\.computer\.links\.group | string |  `url` 
action\_result\.data\.\*\.events\.\*\.computer\.links\.trajectory | string |  `url` 
action\_result\.data\.\*\.events\.\*\.computer\.network\_addresses\.\*\.ip | string | 
action\_result\.data\.\*\.events\.\*\.computer\.network\_addresses\.\*\.mac | string | 
action\_result\.data\.\*\.events\.\*\.event\_type | string | 
action\_result\.data\.\*\.events\.\*\.computer\.user | string | 
action\_result\.data\.\*\.events\.\*\.computer\.hostname | string |  `host name` 
action\_result\.data\.\*\.events\.\*\.id | numeric | 
action\_result\.data\.\*\.events\.\*\.connector\_guid | string | 
action\_result\.data\.\*\.events\.\*\.date | string | 
action\_result\.data\.\*\.events\.\*\.detection | string | 
action\_result\.data\.\*\.events\.\*\.detection\_id | string | 
action\_result\.data\.\*\.events\.\*\.event\_type\_id | numeric | 
action\_result\.data\.\*\.events\.\*\.file\.archived\_file\.disposition | string | 
action\_result\.data\.\*\.events\.\*\.file\.archived\_file\.identity\.sha256 | string | 
action\_result\.data\.\*\.events\.\*\.file\.attack\_details\.application | string | 
action\_result\.data\.\*\.events\.\*\.file\.attack\_details\.attacked\_module | string | 
action\_result\.data\.\*\.events\.\*\.file\.attack\_details\.base\_address | string | 
action\_result\.data\.\*\.events\.\*\.file\.attack\_details\.indicators\.\*\.description | string | 
action\_result\.data\.\*\.events\.\*\.file\.attack\_details\.indicators\.\*\.id | string | 
action\_result\.data\.\*\.events\.\*\.file\.attack\_details\.indicators\.\*\.severity | string | 
action\_result\.data\.\*\.events\.\*\.file\.attack\_details\.indicators\.\*\.short\_description | string | 
action\_result\.data\.\*\.events\.\*\.file\.disposition | string | 
action\_result\.data\.\*\.events\.\*\.file\.file\_name | string |  `file name` 
action\_result\.data\.\*\.events\.\*\.file\.file\_path | string |  `file name`  `file path` 
action\_result\.data\.\*\.events\.\*\.file\.identity\.md5 | string |  `md5` 
action\_result\.data\.\*\.events\.\*\.file\.identity\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.events\.\*\.file\.identity\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.events\.\*\.file\.parent\.disposition | string | 
action\_result\.data\.\*\.events\.\*\.file\.parent\.file\_name | string |  `file name` 
action\_result\.data\.\*\.events\.\*\.file\.parent\.identity\.md5 | string |  `md5` 
action\_result\.data\.\*\.events\.\*\.file\.parent\.identity\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.events\.\*\.file\.parent\.identity\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.events\.\*\.file\.parent\.process\_id | numeric | 
action\_result\.data\.\*\.events\.\*\.group\_guids | string | 
action\_result\.data\.\*\.events\.\*\.isolation\.duration | numeric | 
action\_result\.data\.\*\.events\.\*\.isolation\.user | string | 
action\_result\.data\.\*\.events\.\*\.network\_info\.dirty\_url | string | 
action\_result\.data\.\*\.events\.\*\.network\_info\.local\_ip | string | 
action\_result\.data\.\*\.events\.\*\.network\_info\.local\_port | numeric | 
action\_result\.data\.\*\.events\.\*\.network\_info\.nfm\.direction | string | 
action\_result\.data\.\*\.events\.\*\.network\_info\.nfm\.protocol | string | 
action\_result\.data\.\*\.events\.\*\.network\_info\.parent\.disposition | string | 
action\_result\.data\.\*\.events\.\*\.network\_info\.parent\.file\_name | string | 
action\_result\.data\.\*\.events\.\*\.network\_info\.parent\.identity\.md5 | string | 
action\_result\.data\.\*\.events\.\*\.network\_info\.parent\.identity\.sha1 | string | 
action\_result\.data\.\*\.events\.\*\.network\_info\.parent\.identity\.sha256 | string | 
action\_result\.data\.\*\.events\.\*\.network\_info\.parent\.process\_id | numeric | 
action\_result\.data\.\*\.events\.\*\.network\_info\.remote\_ip | string | 
action\_result\.data\.\*\.events\.\*\.network\_info\.remote\_port | numeric | 
action\_result\.data\.\*\.events\.\*\.scan\.clean | boolean | 
action\_result\.data\.\*\.events\.\*\.scan\.description | string | 
action\_result\.data\.\*\.events\.\*\.scan\.malicious\_detections | numeric | 
action\_result\.data\.\*\.events\.\*\.scan\.scanned\_files | numeric | 
action\_result\.data\.\*\.events\.\*\.scan\.scanned\_paths | numeric | 
action\_result\.data\.\*\.events\.\*\.scan\.scanned\_processes | numeric | 
action\_result\.data\.\*\.events\.\*\.severity | string | 
action\_result\.data\.\*\.events\.\*\.start\_date | string | 
action\_result\.data\.\*\.events\.\*\.start\_timestamp | numeric | 
action\_result\.data\.\*\.events\.\*\.tactics\.\*\.description | string | 
action\_result\.data\.\*\.events\.\*\.tactics\.\*\.external\_id | string | 
action\_result\.data\.\*\.events\.\*\.tactics\.\*\.mitre\_name | string | 
action\_result\.data\.\*\.events\.\*\.tactics\.\*\.mitre\_url | string | 
action\_result\.data\.\*\.events\.\*\.tactics\.\*\.name | string | 
action\_result\.data\.\*\.events\.\*\.techniques\.\*\.data\_sources | string | 
action\_result\.data\.\*\.events\.\*\.techniques\.\*\.description | string | 
action\_result\.data\.\*\.events\.\*\.techniques\.\*\.external\_id | string | 
action\_result\.data\.\*\.events\.\*\.techniques\.\*\.mitre\_name | string | 
action\_result\.data\.\*\.events\.\*\.techniques\.\*\.mitre\_url | string | 
action\_result\.data\.\*\.events\.\*\.techniques\.\*\.name | string | 
action\_result\.data\.\*\.events\.\*\.techniques\.\*\.permissions | string | 
action\_result\.data\.\*\.events\.\*\.techniques\.\*\.platforms | string | 
action\_result\.data\.\*\.events\.\*\.techniques\.\*\.system\_requirements | string | 
action\_result\.data\.\*\.events\.\*\.techniques\.\*\.tactics\_names | string | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.incident\_end\_time | numeric | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.incident\_hunt\_guid | string | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.incident\_remediation | string | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.incident\_report\_guid | string | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.incident\_start\_time | numeric | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.incident\_summary | string | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.incident\_title | string | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.severity | string | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.tactics\.\*\.description | string | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.tactics\.\*\.external\_id | string | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.tactics\.\*\.mitre\_name | string | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.tactics\.\*\.mitre\_url | string | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.tactics\.\*\.name | string | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.techniques\.\*\.data\_sources | string | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.techniques\.\*\.description | string | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.techniques\.\*\.external\_id | string | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.techniques\.\*\.mitre\_name | string | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.techniques\.\*\.mitre\_url | string | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.techniques\.\*\.name | string | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.techniques\.\*\.permissions | string | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.techniques\.\*\.platforms | string | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.techniques\.\*\.system\_requirements | string | 
action\_result\.data\.\*\.events\.\*\.threat\_hunting\.techniques\.\*\.tactics\_names | string | 
action\_result\.data\.\*\.events\.\*\.timestamp | numeric | 
action\_result\.data\.\*\.events\.\*\.timestamp\_nanoseconds | numeric | 
action\_result\.data\.\*\.events\.\*\.vulnerabilities\.\*\.cve | string | 
action\_result\.data\.\*\.events\.\*\.vulnerabilities\.\*\.name | string | 
action\_result\.data\.\*\.events\.\*\.vulnerabilities\.\*\.score | string | 
action\_result\.data\.\*\.events\.\*\.vulnerabilities\.\*\.url | string | 
action\_result\.data\.\*\.events\.\*\.vulnerabilities\.\*\.version | string | 
action\_result\.data\.\*\.metadata\.links\.next | string |  `url` 
action\_result\.data\.\*\.metadata\.links\.self | string |  `url` 
action\_result\.data\.\*\.metadata\.results\.current\_item\_count | numeric | 
action\_result\.data\.\*\.metadata\.results\.index | numeric | 
action\_result\.data\.\*\.metadata\.results\.items\_per\_page | numeric | 
action\_result\.data\.\*\.metadata\.results\.total | numeric | 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.file\_found | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 