[comment]: # " File: README.md"
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
