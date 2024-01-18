# File: timer_connector.py
#
# Copyright (c) 2018-2024 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
import datetime
import json
import re
import sys

import phantom.app as phantom
import pytz
import requests
from bs4 import UnicodeDammit
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class TimerConnector(BaseConnector):

    def __init__(self):
        super(TimerConnector, self).__init__()
        self._state = None
        self._python_version = None

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.
        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """
        try:
            if input_str and self._python_version < 3:
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def initialize(self):
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version.")

        self._state = self.load_state()
        config = self.get_config()
        self._severity = config.get('severity', 'medium')
        self._sensitivity = config.get('sensitivity', 'amber')
        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _format_event_name(self):
        config = self.get_config()
        event_name = self._handle_py_ver_compat_for_input_str(config['event_name'])

        iso_now = datetime.datetime.now(pytz.utc).isoformat()
        label_name = config.get('ingest', {}).get('container_label', '')

        event_name = re.sub(
            r'(^|[^0-9a-zA-Z]+)(\$now)($|[^0-9a-zA-Z]+)',
            r'\g<1>{}\g<3>'.format(iso_now),
            event_name
        )
        event_name = re.sub(
            r'(^|[^0-9a-zA-Z]+)(\$label)($|[^0-9a-zA-Z]+)',
            r'\g<1>{}\g<3>'.format(self._handle_py_ver_compat_for_input_str(label_name)),
            event_name
        )

        return event_name

    def _handle_test_connectivty(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        event_name = self._format_event_name()

        # no suitable investigative function found for using in test connectivity, hence, keeping it as it is
        self.save_progress("Event Name: {}".format(event_name))

        self.save_progress("Test Connectivity Passed")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_on_poll(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        event_name = self._format_event_name()

        container = {
            'name': event_name,
            'run_automation': True,
            'severity': self._severity,
            'sensitivity': self._sensitivity
        }
        self.save_progress("saving the container")
        ret_val, message, container_id = self.save_container(container)
        if phantom.is_fail(ret_val):
            return action_result.set_status(
                phantom.APP_ERROR,
                "Unable to create container: {}".format(message)
            )

        return action_result.set_status(phantom.APP_SUCCESS, "Created Container")

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'on_poll':
            ret_val = self._handle_on_poll(param)
        elif action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivty(param)

        return ret_val


if __name__ == '__main__':

    import argparse

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify
    timeout = 30

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=verify, timeout=timeout)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=verify, data=data, headers=headers, timeout=timeout)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            sys.exit(1)

    if (len(sys.argv) < 2):
        print("No test json specified as input")
        sys.exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = TimerConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
