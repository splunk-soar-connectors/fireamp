# File: fireamp_connector.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Local Imports
from fireamp_consts import *

import base64 as b64
import requests
import simplejson as json
from uuid import UUID


class FireAMPConnector(BaseConnector):
    ACTION_ID_LIST_ENDPOINTS = "list_endpoints"
    ACTION_ID_HUNT_FILE = "hunt_file"
    ACTION_ID_HUNT_IP = "hunt_ip"
    ACTION_ID_HUNT_URL = "hunt_url"
    ACTION_ID_GET_DEVICE_INFO = "get_device_info"

    def __init__(self):
        self._base_url = None

        super(FireAMPConnector, self).__init__()

    def initialize(self):
        """ Called once for every action, all member initializations occur here"""

        config = self.get_config()

        # Get the Base URL from the asset config and so some cleanup
        self._base_url = config.get(AMP_JSON_BASE_URL, BASE_URL)
        if (self._base_url.endswith('/')):
            self._base_url = self._base_url[:-1]

        return phantom.APP_SUCCESS

    def _create_auth_header(self):
        config = self.get_config()
        client_id = config[AMP_JSON_API_CLIENT_ID]
        api_key = config[AMP_JSON_API_KEY]
        # Authtoken is client id an api_key encoded with : between them
        auth_string = '{0}:{1}'.format(client_id, api_key)
        auth = b64.b64encode(auth_string.encode('utf-8')).decode()
        header = {'Authorization': 'Basic {0}'.format(auth)}
        return header

    def _make_rest_call(self, endpoint, method="get", parameters=None):

        url = "{0}{1}".format(self._base_url, endpoint)
        headers = self._create_auth_header()

        request_func = getattr(requests, method)
        if (not request_func):
            return (
                phantom.APP_ERROR,
                "Invalid method call: {0} for requests module".format(method)
            )

        self.send_progress("Making API Call")

        try:
            r = request_func(url, headers=headers, params=parameters)
        except Exception as e:
            # Some error making request
            return (
                phantom.APP_ERROR,
                "REST call to server failed: {}".format(e)
            )

        if (r.status_code != 200):
            if (r.reason == "Not Found"):
                return (phantom.APP_SUCCESS, AMP_ENDPOINT_NOT_FOUND)
            return (
                phantom.APP_ERROR,
                "REST response invalid. Reason: {}".format(
                    json.loads((r.content))['errors'][0]['details'][0])
                )

        try:
            resp_json = r.json()
            return phantom.APP_SUCCESS, resp_json
        except Exception as e:
            # Some error parsing response
            return (
                phantom.APP_ERROR,
                "Error while parsing response: {}".format(e)
            )

    def _test_asset_connectivity(self):

        action_result = ActionResult()

        endpoint = "/v1/version"

        self.save_progress("Testing asset connectivity")

        status_code, resp_json = self._make_rest_call(endpoint)

        # Process errors
        if (phantom.is_fail(status_code)):

            # Dump error messages in the log
            self.debug_print(action_result.get_message())

            # Set the status of the complete connector result
            self.set_status(phantom.APP_ERROR, action_result.get_message())

            # Append the message to display
            self.append_to_message(
                "Test Connectivity Failed. Please check your credentials"
            )

            # return error
            return phantom.APP_ERROR

        # Set the status of the connector result
        return self.set_status_save_progress(
            phantom.APP_SUCCESS,
            "Test Connectivity Passed"
        )

    def _list_endpoints(self, param):

        action_result = self.add_action_result(ActionResult(param))
        endpoint = "/v1/computers"

        action_result.update_summary({'total_endpoints': 0})

        status_code, resp_json = self._make_rest_call(endpoint)
        if (phantom.is_fail(status_code)):
            return action_result.set_status(phantom.APP_ERROR, resp_json)

        action_result.add_data(resp_json)

        metadata = resp_json['metadata']
        if (metadata):
            action_result.update_summary(
                {'total_endpoints': metadata['results']['total']}
            )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _hunt_action(self, action_result, query, check_execution=False):
        endpoint = "/v1/computers/activity"
        params = {"q": query}
        status_code, response = self._make_rest_call(
            endpoint,
            parameters=params
        )

        if (phantom.is_fail(status_code)):
            return action_result.set_status(phantom.APP_ERROR, response)

        if check_execution:
            response['data'] = self._check_file_execution(
                response['data'],
                query
            )

        action_result.add_data(response)

        action_result.set_summary({'device_count': len(response['data'])})

        return phantom.APP_SUCCESS

    def _check_file_execution(self, response_data, file_hash):
        guids = [
            (i, entry['connector_guid'])
            for i, entry
            in enumerate(response_data)
        ]

        for guid in guids:
            endpoint = '/v1/computers/{}/trajectory'.format(guid[1])
            params = {'q': file_hash}
            status_code, response = self._make_rest_call(
                endpoint,
                parameters=params
            )
            response_data[guid[0]]['file_execution_details'] = {
                'executed': False,
                'file_name': '',
                'file_path': '',
                'message': ''
            }
            if phantom.is_fail(status_code):
                response_data[guid[0]]['file_execution_details']['message'] = (
                    'Unable to retrieve execution details. Details - '
                    + str(response)
                )
            else:
                events = (response['data'].get('events') or [])

                for event in events:
                    event_type = event.get('event_type')
                    if(
                        event_type == 'Executed by'
                        and file_hash == event['file']['identity']['sha256']
                    ):
                        response_data[guid[0]]['file_execution_details']['executed'] = True
                        response_data[guid[0]]['file_execution_details']['file_name'] = event['file']['file_name']
                        response_data[guid[0]]['file_execution_details']['file_path'] = event['file']['file_path']
                        response_data[guid[0]]['file_execution_details']['message'] = 'File executed'

                if response_data[guid[0]]['file_execution_details']['message'] == '':
                    response_data[guid[0]]['file_execution_details']['message'] = 'File not executed'

        return response_data

    def _hunt_file(self, param):
        action_result = self.add_action_result(ActionResult(param))
        ret_val = self._hunt_action(
            action_result, param[AMP_JSON_HASH],
            check_execution=param.get('check_execution')
        )
        if (phantom.is_fail(ret_val)):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS)

    def _hunt_ip(self, param):
        action_result = self.add_action_result(ActionResult(param))
        ret_val = self._hunt_action(action_result, param[AMP_JSON_IP])

        if (phantom.is_fail(ret_val)):
            return ret_val
        return action_result.set_status(phantom.APP_SUCCESS)

    def _hunt_url(self, param):
        action_result = self.add_action_result(ActionResult(param))
        ret_val = self._hunt_action(action_result, param[AMP_JSON_URL])

        if (phantom.is_fail(ret_val)):
            return ret_val
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_device_info(self, param):
        action_result = self.add_action_result(ActionResult(param))

        try:

            c_guid = param[AMP_JSON_CONNECTOR_GUID]  # Connector GUID

            UUID(c_guid, version=4)

        except ValueError:

            return action_result.set_status(phantom.APP_ERROR, "Parameter connector_guid failed validation")

        endpoint = "/v1/computers/{0}".format(c_guid)

        status_code, resp_json = self._make_rest_call(endpoint)

        action_result.update_summary({'total_endpoints': 0})

        if (phantom.is_fail(status_code)):
            return action_result.set_status(phantom.APP_ERROR, resp_json)

        elif (resp_json == AMP_ENDPOINT_NOT_FOUND):
            return action_result.set_status(phantom.APP_SUCCESS, AMP_ENDPOINT_NOT_FOUND)

        action_result.update_summary({'total_endpoints': 1})

        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        action = self.get_action_identifier()
        ret_val = phantom.APP_SUCCESS
        if (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_asset_connectivity()
        elif (action == self.ACTION_ID_LIST_ENDPOINTS):
            ret_val = self._list_endpoints(param)
        elif (action == self.ACTION_ID_HUNT_FILE):
            ret_val = self._hunt_file(param)
        elif (action == self.ACTION_ID_HUNT_IP):
            ret_val = self._hunt_ip(param)
        elif (action == self.ACTION_ID_HUNT_URL):
            ret_val = self._hunt_url(param)
        elif (action == self.ACTION_ID_GET_DEVICE_INFO):
            ret_val = self._get_device_info(param)

        return ret_val


if __name__ == '__main__':
    import sys
    import pudb

    pudb.set_trace()
    if (len(sys.argv) < 2):
        print("No test json specified as input")
        exit(0)
    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = FireAMPConnector()
        connector.print_progress_message = True
        r_val = connector._handle_action(json.dumps(in_json), None)
        print(r_val)
    exit(0)
