#Skype Bot 

Implements [Microsoft Chat REST API V3](https://docs.botframework.com/en-us/skype/chat/#conversation-update) client.

Currently Python 2.7 tested only.

Steps to run the bot on your local machine:

1. Register your bot [here](https://dev.botframework.com).

2. Get the bot name, app_id and password.

3. Install [ngrok](https://ngrok.com/download).

4. Create a virtualenv and install skype_bot.

    ```bash
    virtualenv ~/.virtualenv/skype_bot
    source ~/.virtualenv/skype_bot/bin/activate
    pip install git+https://github.com/amironenko/skype_bot.git
    ```
5. Then create a file with contents like:
  ```python
  #!/usr/bin/env python
  import logging
  from skype_bot.bot import Bot

  bot_config = { 'bot_name': 'my-bot',
                 'bot_password': '<your bot password here>',  # example 'UeteHnfdQgieutiYLHTQE9F'
                 'bot_app_id':   '<your app id here>',         # example '4f7bcc06-bb22-4f4a-b44c-51485be54c67'
                 'logging_level': logging.DEBUG,
                 'port': 3978,
                 'hostname': 'localhost'
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
  or just clone it from github:
  ```
  wget https://raw.githubusercontent.com/amironenko/skype_bot/master/run_bot.py
  ```
6. Paste your credentials to the bot_config dictionary.
7. Run the bot:

  ```
  python run_bot.py
  ```
  
8. Run ngrok to make the bot accessible from the Internet:
  
  ```
  ngrok http 3978
  ```
  
  ngrok will keep hanging in interactive mode.
  Find a line like:
  
  ```
  Forwarding                    https://0254f9a6.ngrok.io -> localhost:3978
  ```
  
  It means that your bot is exposed to the Internet at `https://0254f9a6.ngrok.io`.
  Full URI is going to be:

  ```
  https://0254f9a6.ngrok.io/api/messages
  ```
9. Now go and [configure your bot Messaging endpoint](https://dev.botframework.com/bots).

10. Test your bot.

# Tips
To run bot as a WSGI application use `run_app` as a callable object.
