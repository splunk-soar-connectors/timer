**Unreleased**

* Converted Timer to the Splunk SOAR SDK. Requires Splunk SOAR 7.0 or later and Python 3.13.
* Action metadata now lists standard status, message, summary, and supplied poll parameter paths. Actions still return no data rows.
* Test connectivity retains its "Test Connectivity Passed" progress message; its action result now uses the SDK success message.
