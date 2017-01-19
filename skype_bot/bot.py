#!/usr/bin/env python
import requests
import json
import logging
from auth import Auth

from flask import Flask, request


class Bot:
    bot_name = None
    bot_password = None
    bot_app_id = None

    api_url = 'https://api.skype.net'

    bot_endpoint = '/api/messages'

    # default port value, can be overriden in config
    bot_port = 3978
    # default hostname, can be overriden in config
    bot_host = 'localhost'

    app = Flask(__name__)  # Flask app object
    default_handler = None
    relation_update_handler = None
    add_to_contactlist_handler = None
    remove_from_contactlist_handler = None
    logger = logging.getLogger(__name__)

    def send(self, conversation_id, message):
        """
        Function sends a message to a conversation identified by conversation_id
        :param conversation_id:
        :param message: message string
        :return: HTTP response status
        """
        send_url = '/v3/conversations/{}/activities'
        data = {'text': message,
                'type': 'message/text',
                }
        headers = {'Authorization': 'Bearer ' + self.auth.get_bearer_token()}
        post_url = (self.api_url + send_url).format(conversation_id)
        try :
            result = requests.post(url=post_url, data=json.dumps(data), headers=headers)
            return result.status_code
        except Exception as e:
            self.logger.exception(e)
            raise Exception(e)

    def __init__(self, config):
        self.bot_name = config['bot_name']
        self.bot_password = config['bot_password']
        self.bot_app_id = config['bot_app_id']
        if 'port' in config:
            self.bot_port = config['port']
        if 'hostname' in config:
            self.bot_host = config['hostname']
        if 'logging_level' in config:
            logging.basicConfig(level=config['logging_level'],
                                format='%(asctime)s %(levelname)-8s %(name)-15s %(message)s')
        self.auth = Auth(self.bot_app_id, self.bot_password)

        @self.app.route('/api/messages', methods=['POST'])
        def listen():
            """
            Function accepts incoming requests from MS server, parses it and passes to custom handlers.
            Request format example:
                {u'recipient': {u'id': u'28:4f7d6c06-bb77-4f4a-b33c-51485be54c67', u'name': u'duxa-bot'}, u'from': {u'id': u'29:1dHAIi7JbBz8fGKackEJ6fT2Fs5Ov_IsOp1T5tlm1xQE', u'name': u'Andrey Mironenko'}, u'timestamp': u'2016-11-05T18:31:00.795Z', u'channelId': u'skype', u'conversation': {u'id': u'29:1dHAIi7JbBz8fGKackEJ6fT2Fs5Ov_IsOp1T5tlm1xQE'}, u'serviceUrl': u'https://skype.botframework.com', u'action': u'add', u'type': u'contactRelationUpdate', u'id': u'6xsmnHhoMQM'}
                {u'recipient': {u'id': u'28:4f7d6c06-bb77-4f4a-b33c-51485be54c67', u'name': u'duxa-bot'}, u'from': {u'id': u'29:1dHAIi7JbBz8fGKackEJ6fT2Fs5Ov_IsOp1T5tlm1xQE', u'name': u'Andrey Mironenko'}, u'timestamp': u'2016-11-05T18:08:41.59Z', u'channelId': u'skype', u'conversation': {u'id': u'29:1dHAIi7JbBz8fGKackEJ6fT2Fs5Ov_IsOp1T5tlm1xQE'}, u'serviceUrl': u'https://skype.botframework.com', u'action': u'remove', u'type': u'contactRelationUpdate', u'id': u'6Txlawp2K7d'}

            :return: empty response
            """
            self.logger.debug(request.headers)
            if not self.auth.verify_request(request.headers['Authorization']):
                self.logger.info('Unverified request. Ignoring.')
                return ''

            request_json = request.json
            request_type = request_json['type']
            sender_name = request_json['from']['name']
            sender_id = request_json['from']['id']
            conversation_id = request_json['conversation']['id']

            # answer to MS server ping request
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


            answer = self.default_handler(message, request_type, conversation_id, sender_name, sender_id)
            self.send(conversation_id=conversation_id, message=answer)
            return ''

    def set_default_message_handler(self, function):  # get_message(text, type, conversation_id)
        self.default_handler = function

    def set_relation_update_handler(self, function):
        self.relation_update_handler = function

    def run(self, port=None, host=None):
        self.app.run(debug=True, port=self.bot_port, host=self.bot_host)
