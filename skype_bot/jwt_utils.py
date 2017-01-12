import jwt
import OpenSSL.crypto
import requests
import logging
import base64
import json

class JWT_Utils:
    server_keys = []
    # TODO: sort out logging stuff
    logger = logging.getLogger('jwt_utils')
    logger.setLevel('DEBUG')
    logger.addHandler(logging.StreamHandler())

    def __init__(self):
        self.update_server_keys()

    def verify_request(self, auth_header):
        parts = auth_header.split(" ")
        if len(parts) != 2 or parts[0] != 'Bearer' or len(parts[1]) == 0:
            return False
        token = parts[1]
        headers = self._get_headers(token)
        kid = headers['kid']
        public_key = self._get_public_key_by_kid(kid)
        return self._verify_token_signature(token, public_key, headers['alg'])

    def update_server_keys(self):
        try:
            result = requests.get('https://api.aps.skype.com/v1/keys')
            keys = result.json()['keys']
            # TODO: check if keys are correct?
            self.server_keys = keys
            return True
        except Exception as e:
            self.logger.exception(e)
            return False

    def _get_headers(self, token):
        try:
            parts = token.split('.')
            headers = base64.b64decode(parts[0])
            # payload = base64.urlsafe_b64decode(parts[1])
            """
            {
              "typ": "JWT",
              "alg": "RS256",
              "kid": "GCxArXoN8Sqo7PweA7-z65denJQ",
              "x5t": "GCxArXoN8Sqo7PweA7-z65denJQ"
            }
            """

            return json.loads(headers)
        except Exception as e:
            self.logger.exception(e)
            print "Exception: {}".format(e.message)
            return None

    def _get_public_key_by_kid(self, kid):
        # try:
            b64_der_cert = ''
            cert_found_by_key = False
            for key in self.server_keys:
                if key['kid'] == kid:
                    b64_der_cert = key['x5c'][0]
                    cert_found_by_key = True
                    break
            if not cert_found_by_key:
                return None
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, base64.b64decode(b64_der_cert))
            der_pub_key = x509.get_pubkey()
            pem_pub_key = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, der_pub_key)
            return pem_pub_key
        # except Exception as e:
        #     self.logger.exception(e)
        #     print "Exception {}".format(e.message)
        #     return None

    def _verify_token_signature(self, token, pem_pub_key, algorithm):
        try:
            jwt.decode(token, pem_pub_key, verify=True, algorithms=[algorithm], options={'verify_aud': False})
            return True
        except Exception as e:
            self.logger.exception(e)
            return False