#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import base64
import urlparse
import json
from tlslite.utils import keyfactory
import oauth2 as oauth
import time


jira_server_url = "http://bug.chenyee.com:8080"
headers = {"Content-Type": "application/json"}


class SignatureMethod_RSA_SHA1(oauth.SignatureMethod):
    name = 'RSA-SHA1'

    def signing_base(self, request, consumer, token):
        if not hasattr(request, 'normalized_url') or request.normalized_url is None:
            raise ValueError("Base URL for request is not set.")

        sig = (
            oauth.escape(request.method),
            oauth.escape(request.normalized_url),
            oauth.escape(request.get_normalized_parameters()),
        )

        key = '%s&' % oauth.escape(consumer.secret)
        if token:
            key += oauth.escape(token.secret)
        raw = '&'.join(sig)
        return key, raw

    def sign(self, request, consumer, token):
        """Builds the base signature string."""
        key, raw = self.signing_base(request, consumer, token)

        with open('./oauth_key/mykey.pem', 'r') as f:
            data = f.read()
        privateKeyString = data.strip()

        privatekey = keyfactory.parsePrivateKey(privateKeyString)
        signature = privatekey.hashAndSign(raw)

        return base64.b64encode(signature)


def main(orig_args):
    reload(sys)
    sys.setdefaultencoding('utf-8')
    consumer_key = 'OauthKey'
    consumer_secret = 'dont_care'
    consumer = oauth.Consumer(consumer_key, consumer_secret)

    access_token = {'oauth_token': 'QHnpXBfHjXhYKfTMVDLMTyInQCefANgv', 'oauth_token_secret': 'k20W95a4ncIhSwBAcvlrXsIQn1IlZzcK'}
    accessToken = oauth.Token(access_token['oauth_token'], access_token[
                              'oauth_token_secret'])
    client = oauth.Client(consumer, accessToken)
    client.set_signature_method(SignatureMethod_RSA_SHA1())

    project_key = orig_args[0]
    version_name = orig_args[1]
    version_desc = orig_args[2]
    create_version_url = jira_server_url + "/rest/api/2/version"
    release_date = time.strftime('%Y-%m-%d', time.localtime(time.time()))

    version_info = {
        "description": version_desc,
        "name": version_name,
        "archived": False,
        "released": True,
        "releaseDate": release_date,
        "project": project_key,
    }

    jversion_info = json.dumps(version_info)
    resp, content = client.request(method="POST", uri=create_version_url, headers=headers, body=jversion_info)

    if resp['status'] != '201':
        errmsg = 'Create version for ' + project_key + " failed!" + str(resp)
        raise Exception(errmsg)

if __name__ == '__main__':
    main(sys.argv[1:])
