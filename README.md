[comment]: # "Auto-generated SOAR connector documentation"
# Timer

Publisher: Splunk  
Connector Version: 2\.0\.13  
Product Vendor: Phantom  
Product Name: Timer  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.9\.39220  

This app will generate an empty event which can be used to kick off a playbook at scheduled intervals

[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2018-2022 Splunk Inc."
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
## Event Naming

The **event_name** configuration option will be used as the name of each newly created event.
Optionally, there are two possible values that you can put into this in order to have dynamic names.

-   $label
-   $now

These will be appropriately substituted. For example, if you set **event_name** to "$label event,
created on $now", then a created event could have the name "Email event, created on
2018-01-24T20:02:56.139008+00:00". This timestamp will always be in UTC.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Timer asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**event\_name** |  required  | string | Name of the created event
**placeholder** |  optional  | ph | Placeholder
**severity** |  optional  | string | Severity of the created event
**sensitivity** |  optional  | string | Sensitivity of the created event

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[on poll](#action-on-poll) - Create one empty event to kick off a playbook  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'on poll'
Create one empty event to kick off a playbook

Type: **ingest**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start\_time** |  optional  | Parameter Ignored in this app | numeric | 
**end\_time** |  optional  | Parameter Ignored in this app | numeric | 
**container\_id** |  optional  | Parameter Ignored in this app | numeric | 
**container\_count** |  optional  | Parameter Ignored in this app | numeric | 
**artifact\_count** |  optional  | Parameter Ignored in this app | numeric | 

#### Action Output
No Output