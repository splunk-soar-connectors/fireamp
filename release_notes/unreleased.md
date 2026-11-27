**Unreleased**

* Migrated the connector to the Splunk SOAR SDK. Requires Splunk SOAR 7.0.0 or later and Python 3.13; Python 3.9 is no longer supported.
* Added the generic **make request** action using the asset's API credentials.
* Corrected output contracts: IP, group and technique arrays expose item paths (`.*`); isolation availability is a boolean; invalid file-list fields and unused summaries are no longer advertised. Update playbooks using the affected paths.
* **get device trajectory** now reports the number of returned events in `total_trajectories` instead of the number of response envelope keys.
* Empty **list filelists** results and duplicate **add listitem** responses now return no data rows. The SDK connectivity action identifier is `test_connectivity`.
