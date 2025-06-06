# Timer

Publisher: Splunk \
Connector Version: 2.0.17 \
Product Vendor: Phantom \
Product Name: Timer \
Minimum Product Version: 4.9.39220

This app will generate an empty event which can be used to kick off a playbook at scheduled intervals

## Event Naming

The **event_name** configuration option will be used as the name of each newly created event.
Optionally, there are two possible values that you can put into this in order to have dynamic names.

- $label
- $now

These will be appropriately substituted. For example, if you set **event_name** to "$label event,
created on $now", then a created event could have the name "Email event, created on
2018-01-24T20:02:56.139008+00:00". This timestamp will always be in UTC.

### Configuration variables

This table lists the configuration variables required to operate Timer. These variables are specified when configuring a Timer asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**event_name** | required | string | Name of the created event |
**severity** | optional | string | Severity of the created event |
**sensitivity** | optional | string | Sensitivity of the created event |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration \
[on poll](#action-on-poll) - Create one empty event to kick off a playbook

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'on poll'

Create one empty event to kick off a playbook

Type: **ingest** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Parameter Ignored in this app | numeric | |
**end_time** | optional | Parameter Ignored in this app | numeric | |
**container_id** | optional | Parameter Ignored in this app | numeric | |
**container_count** | optional | Parameter Ignored in this app | numeric | |
**artifact_count** | optional | Parameter Ignored in this app | numeric | |

#### Action Output

No Output

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
