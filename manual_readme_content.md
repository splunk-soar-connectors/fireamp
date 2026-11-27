#### To Generate API Credentials

- Go to Accounts >> API Credentials
- Click New API Credential to generate an API key for your application. You can enter the name of
  the application for reference purposes and assign a scope of read only or read and write
  permissions as per your requirements.
- Store this generated API key somewhere secure since it cannot be retrieved after closing the
  window.

#### Base URL

- There are 3 different Base URLs available:

  - api.amp.cisco.com
  - api.apjc.amp.cisco.com
  - api.eu.amp.cisco.com

- To find the Base URL, Go to Accounts >> API Credentials

- Click on **View API Documentation** . It will redirect to the Endpoints API page. Check the
  value of the **api_host** parameter in the URL.

- If Base URL is not provided, **https://api.amp.sourcefire.com/** will be used as the Base URL by
  default.

#### Make request

Use **make request** for Secure Endpoint API endpoints without a dedicated action. Requests use
HTTP Basic authentication with this asset's API Client ID and API Key. The credential's permissions
and the target API determine which operations are available.

Provide an API path relative to **Base URL**, including its API version, such as `/v1/computers`,
`/v1/events`, or `/v1/computers/{connector_guid}/isolation`. Replace placeholders with actual values.
Absolute URLs are rejected. Redirects are returned without being followed.

- **http_method**: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, or `OPTIONS`.
- **headers**: an optional JSON object with string values, such as
  `{"Content-Type":"application/json"}`. Asset authentication sets the Authorization header.
- **query_parameters**: an optional JSON object such as `{"hostname[]":"host.example.com"}` or a
  query string such as `?limit=100&offset=0`. Parameters can also appear in the endpoint.
- **body**: the request body. JSON is validated when the content type is JSON. For form or text
  bodies, set the corresponding Content-Type header and supply the encoded body.
- **timeout**: a positive number of seconds; the default is 30.
- **verify_ssl**: whether to verify the server certificate; the default is true.

The action returns the HTTP `status_code` and raw `response_body`, including HTTP error responses.
Transport failures fail the action. A request retrieves one API response; follow pagination through
additional requests when needed.

Examples:

| Operation | Method | Endpoint | Additional input |
| --- | --- | --- | --- |
| List endpoints | GET | `/v1/computers` | query_parameters: `{"limit":100}` |
| Hunt an IP | GET | `/v1/computers/activity` | query_parameters: `{"q":"192.0.2.1"}` |
| Get events | GET | `/v1/events` | query_parameters: `{"connector_guid":"<guid>"}` |
| Isolate endpoint | PUT | `/v1/computers/<guid>/isolation` | None |
| End isolation | DELETE | `/v1/computers/<guid>/isolation` | None |
| Change group | PATCH | `/v1/computers/<guid>` | body: `{"group_guid":"<group-guid>"}` |
| Add a hash | POST | `/v1/file_lists/<list-guid>/files/<sha256>` | None |
| Remove a hash | DELETE | `/v1/file_lists/<list-guid>/files/<sha256>` | None |

#### SDK compatibility

This version requires Splunk SOAR 7.0.0 or later and Python 3.13. IP address arrays, group GUID arrays,
and technique array fields use item recommendation paths ending in `.*`. Isolation availability is
a boolean. Invalid legacy object paths and summaries that the actions never produced are omitted.
The source comments and contract tests identify those corrections.

`executed_only` remains a legacy input for **get device trajectory** and does not filter results.
`limit` controls the API page size for named paginated actions; they collect all available pages.
