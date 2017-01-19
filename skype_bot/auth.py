import jwt
import OpenSSL.crypto
import requests
import logging
import base64
import json
import time

bearer_token_exp_period = 3600

server_keys_exp_period = 3600


class Auth:
    server_keys = []
    server_keys_exp_time = None

    bearer_token = None
    bearer_token_exp_time = None

    auth_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'

    bot_app_id = None
    bot_password = None

    # TODO: sort out logging stuff
    logger = logging.getLogger('auth')
    # logger.setLevel('DEBUG')
    # logger.addHandler(logging.StreamHandler())

    def __init__(self, bot_app_id, bot_password):
        self.bot_app_id = bot_app_id
        self.bot_password = bot_password

        self.get_bearer_token()
        self.update_server_keys()

    def get_bearer_token(self):
        """
        Function provides authentication against MS servers and returns Bearer token.
        Token is cached for 1 hour.
        :return: bearer token to be used in send() function
        """

        # check if cached token is still valid
        if self.bearer_token is not None and time.time() < self.bearer_token_exp_time:
            return self.bearer_token

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
            self.bearer_token_exp_time = time.time() + bearer_token_exp_period
            self.bearer_token = bearer_token
            return self.bearer_token
        else:
            raise Exception('auth failed')
            self.bearer_token = None

    def verify_request(self, auth_header):
        """
        Function validates incoming requests's Authorization header
        :param auth_header: Authorization header of incoming request
        :return:
        """
        parts = auth_header.split(" ")
        if len(parts) != 2 or parts[0] != 'Bearer' or len(parts[1]) == 0:
            self.logger.error('Malformed Authorization header: {}')
            return False
        token = parts[1]
        headers = self._get_headers(token)
        kid = headers['kid']  # getting the public key id
        public_key = self._get_public_key_by_kid(kid)
        return self._verify_token_signature(token, public_key, headers['alg'])

    def update_server_keys(self):
        if self.server_keys and time.time() < self.bearer_token_exp_time:
            return self.server_keys
        try:
            result = requests.get('https://api.aps.skype.com/v1/keys')
            keys = result.json()['keys']
            # TODO: check if keys are correct?
            self.server_keys = keys
            self.server_keys_exp_time = time.time() + server_keys_exp_period
            return self.server_keys
        except Exception as e:
            self.logger.exception(e)
            raise Exception("Couldn't update server keys")

    def _get_headers(self, token):
        """
        Function decodes token and parses it.
        Headers example:
         {
              "typ": "JWT",
              "alg": "RS256",
              "kid": "GCxArXoN8Sqo7PweA7-z65denJQ",
              "x5t": "GCxArXoN8Sqo7PweA7-z65denJQ"
            }
        :param token: Incoming request's Authorization token
        :return: decoded token header as a dictionary
        """
        try:
            parts = token.split('.')
            headers = base64.b64decode(parts[0])
            return json.loads(headers)
        except Exception as e:
            self.logger.exception(e)
            raise Exception('Token cannot be parsed: {}'.format(token))

    def _get_public_key_by_kid(self, kid):
        """
        Function looks up a certificate by key id in the list of server keys, extracts public key and encodes it to PEM format.
        :param kid: key id (taken from token header)
        :return: public key in PEM format
        """
        b64_der_cert = ''
        cert_found_by_key = False
        for key in self.server_keys:
            if key['kid'] == kid:
                b64_der_cert = key['x5c'][0]
                cert_found_by_key = True
                break
        if not cert_found_by_key:
            self.logger.error('Public key with kid = "{}" is absent'.format(kid))
            raise Exception('Public key with kid = {} cannot be found'.format(kid))
        try:
            # parse certificate and load into x509 object
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, base64.b64decode(b64_der_cert))
            # extract public key in DER format
            der_pub_key = x509.get_pubkey()
            # dump in PEM format
            pem_pub_key = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, der_pub_key)
            return pem_pub_key

        except Exception as e:
            self.logger.exception(e)
            raise Exception('Public key cannot be extracted. Key id is: {}'.format(kid))

    def _verify_token_signature(self, token, pem_pub_key, algorithm):
        try:
            jwt.decode(token, pem_pub_key, verify=True, algorithms=[algorithm], options={'verify_aud': False})
            return True
        except Exception as e:
            self.logger.exception(e)
            return False
