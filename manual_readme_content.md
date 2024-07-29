[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2024 Splunk Inc."
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
