## Event Naming

The **event_name** configuration option will be used as the name of each newly created event.
Optionally, there are two possible values that you can put into this in order to have dynamic names.

- $label
- $now

These will be appropriately substituted. For example, if you set **event_name** to "$label event,
created on $now", then a created event could have the name "Email event, created on
2018-01-24T20:02:56.139008+00:00". This timestamp will always be in UTC.
