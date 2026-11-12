# Timer

Publisher: Splunk <br>
Connector Version: 2.0.23 <br>
Product Vendor: Phantom <br>
Product Name: Timer <br>
Minimum Product Version: 7.0.0

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

[on poll](#action-on-poll) - Create one empty event to kick off a playbook <br>
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration.

## action: 'on poll'

Create one empty event to kick off a playbook

Type: **ingest** <br>
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

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.start_time | numeric | | |
action_result.parameter.end_time | numeric | | |
action_result.parameter.container_id | numeric | | |
action_result.parameter.container_count | numeric | | |
action_result.parameter.artifact_count | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration.

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
