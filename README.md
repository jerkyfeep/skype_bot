This skype bot uses [Microsoft Chat REST API V3](https://docs.botframework.com/en-us/skype/chat/#conversation-update)

Now only text messages are supported.
You should first register your bot [here](https://dev.botframework.com).
After registration you should know bot name, bot app id and bot password.
Then you can expose your bot to the Internet. Valid SSL certificate is required.
For dev purposes locally running bot can be exposed to the Internet using [Ngrok](https://ngrok.com/).


Default bot endpoint is '/api/messages' at 'localhost:3978'.

Code example:

```python

bot_config = { 'bot_name': 'my-bot',
               'bot_password': '<your bot password here>',  # example 'UeteHnfdQgieutiYLHTQE9F'
               'bot_app_id':   '<your app id here>',         # example '4f7bcc06-bb22-4f4a-b44c-51485be54c67'
               'logging_level': logging.DEBUG,
              }


def handle_message(text, type, conversation_id, sender_name, sender_id):
    print "Message from {} received. Text: {}, type: {}, conversion_id: {}".format(sender_name, text, type,
                                                                                   conversation_id)
    return 'message received'


my_bot = Bot(bot_config)
my_bot.set_default_message_handler(handle_message)
run_app = Bot.app

if __name__ == "__main__":
    my_bot.run()

```

To run bot as a WSGI application use `run_app` as a callable object.
