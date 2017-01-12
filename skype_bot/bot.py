#!/usr/bin/env python
import requests
import json
import logging
from jwt_utils import JWT_Utils
import time

from flask import Flask, request


class Bot:
    bot_name = None
    bot_password = None
    bot_app_id = None

    bearer_token = None
    bearer_token_exp_time = None

    api_url = 'https://api.skype.net'
    auth_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
    bot_endpoint = '/api/messages'
    bot_port = 3978
    bot_host = 'localhost'

    app = Flask(__name__)  # Flask app object
    default_handler = None
    relation_update_handler = None
    add_to_contactlist_handler = None
    remove_from_contactlist_handler = None
    logger = logging.getLogger(__name__)

    def get_bearer_token(self):
        if self.bearer_token is not None and time.time() < self.bearer_token_exp_time:
            return
        data = {'client_id': self.bot_app_id,
                'client_secret': self.bot_password,
                'grant_type': 'client_credentials',
                'scope': 'https://graph.microsoft.com/.default',
                }

        header = {'Content-Type': 'application/x-www-form-urlencoded'}

        result = requests.post(self.auth_url, data=data, headers=header)

        if result.status_code == 200:
            bearer_token = json.loads(result.content)['access_token']
            self.logger.debug('token received: {}'.format(bearer_token))
            self.bearer_token_exp_time = time.time() + 3600
            self.bearer_token = bearer_token
        else:
            raise Exception('auth failed')
            self.bearer_token = None

    def send(self, conversation_id, message):
        send_url = '/v3/conversations/{}/activities'
        data = {'text': message,
                'type': 'message/text',
                }
        headers = {'Authorization': 'Bearer ' + self.bearer_token}
        post_url = (self.api_url + send_url).format(conversation_id)
        result = requests.post(url=post_url, data=json.dumps(data), headers=headers)

        return result.status_code

    def __init__(self, config):
        self.bot_name = config['bot_name']
        self.bot_password = config['bot_password']
        self.bot_app_id = config['bot_app_id']
        self.get_bearer_token()
        self.jwt_utils = JWT_Utils()
        if 'logging_level' in config:
            logging.basicConfig(level=config['logging_level'],
                                format='%(asctime)s %(levelname)-8s %(name)-15s %(message)s')

        @self.app.route('/api/messages', methods=['POST'])
        def listen():
            self.logger.debug(request.headers)

            if not self.jwt_utils.verify_request(request.headers['Authorization']):
                self.logger.info('unverified request. ignoring.')
                return ''

            request_json = request.json
            request_type = request_json['type']
            sender_name = request_json['from']['name']
            sender_id = request_json['from']['id']
            conversation_id = request_json['conversation']['id']

            # answer to MS server pint request
            if request_type == 'ping':
                self.send(conversation_id=conversation_id, message='')
                return ''
            # handle relation update request
            if request_type == 'contactRelationUpdate':
                action = request_json['action']
                # call user handler if it's set
                if self.relation_update_handler is not None:
                    self.relation_update_handler(action=action, sender_id=sender_id, sender_name=sender_name)
                if action == 'add':
                    # add to contact list
                    self.logger.info('Bot was added to the contact list of {}'.format(request_json['from']['name']))
                    if self.add_to_contactlist_handler is not None:
                        hello_message = self.add_to_contactlist_handler(sender_id=sender_id, sender_name=sender_name)
                        self.send(conversation_id=conversation_id, message=hello_message)

                if action == 'remove':
                    # remove request_json['from']['name'] from contact list
                    self.logger.info('Bot was removed from the contact list of {}'.format(request_json['from']['name']))
                    if self.remove_from_contactlist_handler is not None:
                        self.remove_from_contactlist_handler(sender_id=sender_id, sender_name=sender_name)
                return ''
            # all other requests
            self.logger.debug(request.json)
            message = request_json['text']

            # DEBUG:bot:{u'recipient': {u'id': u'28:4f7d6c06-bb77-4f4a-b33c-51485be54c67', u'name': u'duxa-bot'}, u'from': {u'id': u'29:1dHAIi7JbBz8fGKackEJ6fT2Fs5Ov_IsOp1T5tlm1xQE', u'name': u'Andrey Mironenko'}, u'timestamp': u'2016-11-05T18:31:00.795Z', u'channelId': u'skype', u'conversation': {u'id': u'29:1dHAIi7JbBz8fGKackEJ6fT2Fs5Ov_IsOp1T5tlm1xQE'}, u'serviceUrl': u'https://skype.botframework.com', u'action': u'add', u'type': u'contactRelationUpdate', u'id': u'6xsmnHhoMQM'}
            # DEBUG:bot:{u'recipient': {u'id': u'28:4f7d6c06-bb77-4f4a-b33c-51485be54c67', u'name': u'duxa-bot'}, u'from': {u'id': u'29:1dHAIi7JbBz8fGKackEJ6fT2Fs5Ov_IsOp1T5tlm1xQE', u'name': u'Andrey Mironenko'}, u'timestamp': u'2016-11-05T18:08:41.59Z', u'channelId': u'skype', u'conversation': {u'id': u'29:1dHAIi7JbBz8fGKackEJ6fT2Fs5Ov_IsOp1T5tlm1xQE'}, u'serviceUrl': u'https://skype.botframework.com', u'action': u'remove', u'type': u'contactRelationUpdate', u'id': u'6Txlawp2K7d'}

            answer = self.default_handler(message, request_type, conversation_id, sender_name, sender_id)
            self.send(conversation_id=conversation_id, message=answer)
            return ''

    def set_default_message_handler(self, function):  # get_message(text, type, conversation_id)
        self.default_handler = function

    def set_relation_update_handler(self, function):
        self.relation_update_handler = function

    def run(self, port=3978, host='localhost'):
        self.app.run(debug=True, port=port, host=host)
