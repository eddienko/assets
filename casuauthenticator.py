"""
Custom Authenticator to use generic OAuth2 with JupyterHub
"""


import sys
import json
import os
import base64
import urllib
import random
import string
import hashlib

from tornado.auth import OAuth2Mixin
from tornado import web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode, Dict, Bool

from oauthenticator.oauth2 import OAuthLoginHandler, OAuthenticator


class GenericEnvMixin(OAuth2Mixin):
    _OAUTH_ACCESS_TOKEN_URL = os.environ.get('OAUTH2_TOKEN_URL', '')
    _OAUTH_AUTHORIZE_URL = os.environ.get('OAUTH2_AUTHORIZE_URL', '')


class GenericLoginHandler(OAuthLoginHandler, GenericEnvMixin):
    def get_code_challenge(self):
        code_verifier = self.authenticator.code_verifier
        code_challenge = hashlib.sha256(code_verifier).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8').replace('=', '')
        return code_challenge

    def get(self):
        redirect_uri = self.authenticator.get_callback_url(self)
        self.log.info('OAuth redirect: %r', redirect_uri)
        state = self.get_state()
        self.set_state_cookie(state)
        params = {'state': state, 'approval_prompt': 'auto', 'code_challenge_method': 'S256', 'code_challenge': self.get_code_challenge()}
        params.update(self.authenticator.extra_params)
        self.authorize_redirect(
            redirect_uri=redirect_uri,
            client_id=self.authenticator.client_id,
            scope=["read"],
            extra_params=params,
            response_type='code')

class HubAuthenticator(OAuthenticator):

    login_service = Unicode(
        "GenericOAuth2",
        config=True
    )

    login_handler = GenericLoginHandler

    userdata_url = Unicode(
        os.environ.get('OAUTH2_USERDATA_URL', ''),
        config=True,
        help="Userdata url to get user data login information"
    )
    token_url = Unicode(
        os.environ.get('OAUTH2_TOKEN_URL', ''),
        config=True,
        help="Access token endpoint URL"
    )
    extra_params = Dict(
        help="Extra parameters for first POST request"
    ).tag(config=True)

    username_key = Unicode(
        os.environ.get('OAUTH2_USERNAME_KEY', 'username'),
        config=True,
        help="Userdata username key from returned json for USERDATA_URL"
    )
    userdata_params = Dict(
        help="Userdata params to get user data login information"
    ).tag(config=True)

    userdata_method = Unicode(
        os.environ.get('OAUTH2_USERDATA_METHOD', 'GET'),
        config=True,
        help="Userdata method to get user data login information"
    )
    userdata_token_method = Unicode(
        os.environ.get('OAUTH2_USERDATA_REQUEST_TYPE', 'header'),
        config=True,
        help="Method for sending access token in userdata request. Supported methods: header, url. Default: header"
    )

    tls_verify = Bool(
        os.environ.get('OAUTH2_TLS_VERIFY', 'True').lower() in {'true', '1'},
        config=True,
        help="Disable TLS verification on http request"
    )

    basic_auth = Bool(
        os.environ.get('OAUTH2_BASIC_AUTH', 'True').lower() in {'true', '1'},
        config=True,
        help="Disable basic authentication for access token request"
    )

    @property
    def code_verifier(self):
        try:
            return self._code_verifier
        except:
            code_verifier = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(43, 128)))
            code_verifier = base64.urlsafe_b64encode(code_verifier.encode('utf-8'))
            self._code_verifier = code_verifier
            return self._code_verifier

    async def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        print code)
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        params = dict(
            redirect_uri=self.get_callback_url(handler),
            code=code,
            code_verifier=self.code_verifier,
            grant_type='authorization_code'
        )
        params.update(self.extra_params)

        if self.token_url:
            url = self.token_url
        else:
            raise ValueError("Please set the OAUTH2_TOKEN_URL environment variable")

        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub"
        }
        headers = {}

        if self.basic_auth:
            b64key = base64.b64encode(
                bytes(
                    "{}:{}".format(self.client_id, self.client_secret),
                    "utf8"
                )
            )
            headers.update({"Authorization": "Basic {}".format(b64key.decode("utf8"))})
            headers['HTTP_AUTHORIZATION'] = headers['Authorization']

        req = HTTPRequest(url,
                          method="POST",
                          headers=headers,
                          validate_cert=self.tls_verify,
                          body=json.dumps(params)  # Body is required for a POST...
                          )

        resp = await http_client.fetch(req)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        print('****', resp_json)

        access_token = resp_json['access_token']
        refresh_token = resp_json.get('refresh_token', None)
        token_type = resp_json['token_type']
        scope = resp_json.get('scope', '')
        if (isinstance(scope, str)):
            scope = scope.split(' ')

        # Determine who the logged in user is
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "{} {}".format(token_type, access_token)
        }
        if self.userdata_url:
            url = url_concat(self.userdata_url, self.userdata_params)
        else:
            raise ValueError("Please set the OAUTH2_USERDATA_URL environment variable")

        if self.userdata_token_method == "url":
            url = url_concat(self.userdata_url, dict(access_token=access_token))

        req = HTTPRequest(url,
                          method=self.userdata_method,
                          headers=headers,
                          validate_cert=self.tls_verify,
                          )
        resp = await http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        if not resp_json.get(self.username_key):
            self.log.error("OAuth user contains no key %s: %s", self.username_key, resp_json)
            return

        if not resp_json.get("jupyter", False):
            self.log.info("User not allowed to run Jupyter")
            return

        return {
            'name': resp_json.get(self.username_key),
            'jupyter': resp_json["jupyter"],
            'auth_state': {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'oauth_user': resp_json,
                'scope': scope,
            }
        }

