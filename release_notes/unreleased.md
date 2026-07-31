**Unreleased**

* Validate device trajectory connector GUIDs before constructing API paths.
* Validate change-policy group and policy GUIDs before constructing API paths.
* Require unique exact group and policy name matches and encode query parameters safely.
* Report missing containment targets as errors instead of successful actions.
* Collect every Secure Endpoint API result page for listing and hunting actions.
* Mark the mutating `change policy` action as non-read-only.
* Mark the mutating `change group` action as non-read-only.
