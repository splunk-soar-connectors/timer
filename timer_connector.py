# --
# File: timer_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from timer_consts import *
import re
import json
import pytz
import requests
import datetime


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class TimerConnector(BaseConnector):

    def __init__(self):
        super(TimerConnector, self).__init__()
        self._state = None

    def initialize(self):
        self._state = self.load_state()
        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _format_event_name(self):
        config = self.get_config()
        event_name = config['event_name']

        iso_now = datetime.datetime.now(pytz.utc).isoformat()
        label_name = config.get('ingest', {}).get('container_label', '')

        event_name = re.sub(
            r'(^|[^0-9a-zA-Z]+)(\$now)($|[^0-9a-zA-Z]+)',
            r'\g<1>{}\g<3>'.format(iso_now),
            event_name
        )
        event_name = re.sub(
            r'(^|[^0-9a-zA-Z]+)(\$label)($|[^0-9a-zA-Z]+)',
            r'\g<1>{}\g<3>'.format(label_name),
            event_name
        )

        return event_name

    def _handle_test_connectivty(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        event_name = self._format_event_name()

        self.save_progress("Event Name: {}".format(event_name))
        self.save_progress("Test Connectivity Passed")

        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_on_poll(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        event_name = self._format_event_name()

        container = {
            'name': event_name,
            'run_automation': True
        }

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

    import sys
    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = TimerConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
