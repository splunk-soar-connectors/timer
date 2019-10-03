# File: timer_connector.py
# Copyright (c) 2018-2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

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
        config = self.get_config()
        self._severity = config.get('severity', 'medium')
        self._sensitivity = config.get('sensitivity', 'amber')
        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _format_event_name(self):
        config = self.get_config()
        event_name = config['event_name']

        iso_now = datetime.datetime.now(pytz.utc).isoformat()
        label_name = config.get('ingest', {}).get('container_label', '')
        self._iso_now = iso_now

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
        create_artifact_instead = self.get_config().get("create_artifact_instead")
        create_artifact = True if create_artifact_instead else self.get_config().get("create_artifact")
        existing_event_id = self.get_config().get("existing_event_id")

        # configured existing_event_id takes precedence
        if existing_event_id:
            if 'existing_event_id' in self._state:
                self._state['existing_event_id']

        # if existing_event_id was not provided, use the saved event if available otherwise create new one
        if create_artifact_instead and not existing_event_id:
            existing_event_id = self._state.get('existing_event_id')

        if create_artifact:
            artifacts = [{
                'name': event_name if create_artifact_instead else "Timer Artifact",
                'severity': self._severity,
                'cef': {
                    'time': str(self._iso_now),
                },
                'run_automation': True,
            }]
        else:
            artifacts = []

        if not existing_event_id:
            container = {
                'name': event_name,
                'run_automation': True,
                'severity': self._severity,
                'sensitivity': self._sensitivity,
                'artifacts': artifacts,
                'run_automation': False,
            }

            ret_val, message, container_id = self.save_container(container)
            if phantom.is_fail(ret_val):
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to create container: {}".format(message)
                )

            if create_artifact_instead and not existing_event_id:
                self._state['existing_event_id'] = container_id

            return action_result.set_status(phantom.APP_SUCCESS, "Created Container")

        else:
            print(artifacts[0].update({'container_id': existing_event_id}))
            artifacts[0].update({'container_id': existing_event_id})
            ret_val, message, artifact_id = self.save_artifact(artifacts[0])
            if phantom.is_fail(ret_val):
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to create artifact: {}".format(message)
                )

            return action_result.set_status(phantom.APP_SUCCESS, "Created artifact")

    def _handle_manage_timer(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        action = param['action']
        event_id = param.get('existing_event_id')

        if self.get_config().get("existing_event_id"):
            return action_result.set_status(phantom.APP_SUCCESS,"Cannot get/set/clear saved existing event id when configured into asset")

        if action == "get_saved_event_id":
            event_id = self._state['existing_event_id']
            action_result.update_summary({'event_id': event_id})
            action_result.add_data({'event_id': event_id})
            return action_result.set_status(phantom.APP_SUCCESS)

        elif action == "set_saved_event_id":
            if event_id:
                self._state['existing_event_id'] = event_id
                return action_result.set_status(phantom.APP_SUCCESS)

            else:
                return action_result.set_status(phantom.APP_ERROR,"Error: event_id not provided")

        elif action == "clear_saved_event_id":
                if 'existing_event_id' in self._state:
                    del self._state['existing_event_id']
                return action_result.set_status(phantom.APP_SUCCESS)
            
        return action_result.set_status(phantom.APP_ERROR, "Error: unknown action; {}".format(action))


    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'on_poll':
            ret_val = self._handle_on_poll(param)

        elif action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivty(param)

        elif action_id == 'manage_timer':
            ret_val = self._handle_manage_timer(param)

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
