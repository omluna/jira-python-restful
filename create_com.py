#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import base64
import urlparse
import json
from tlslite.utils import keyfactory
import oauth2 as oauth


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

        with open('/Users/mmuunn/Documents/Works/jira/jira-python-restful/oauth_key/mykey.pem', 'r') as f:
            data = f.read()
        privateKeyString = data.strip()

        privatekey = keyfactory.parsePrivateKey(privateKeyString)
        signature = privatekey.hashAndSign(raw)

        return base64.b64encode(signature)

consumer_key = 'OauthKey'
consumer_secret = 'dont_care'
consumer = oauth.Consumer(consumer_key, consumer_secret)
access_token = {'oauth_token': 'QHnpXBfHjXhYKfTMVDLMTyInQCefANgv', 'oauth_token_secret': 'k20W95a4ncIhSwBAcvlrXsIQn1IlZzcK'}
accessToken = oauth.Token(access_token['oauth_token'], access_token[
    'oauth_token_secret'])
client = oauth.Client(consumer, accessToken)
client.set_signature_method(SignatureMethod_RSA_SHA1())

jira_server_url = "http://bug.chenyee.com:8080"
headers = {"Content-Type": "application/json"}
mother_project_url = 'http://bug.chenyee.com:8080/rest/api/2/project'

resp, projects = client.request(mother_project_url, "GET")
projects_dir = json.loads(projects)
project_keys = []
for project in projects_dir:
    print project['key']
    project_keys.append(project['key'])


try:
    project_keys.remove('TEMP')
    project_keys.remove('TRANSTOOL')
    project_keys.remove('TESTTOOLS')
    project_keys.remove('SCLUB')
    project_keys.remove('OA')
    project_keys.remove('D2SHOP')
except:
    pass

#project_keys
#com_template = {
#    "name": u"T-TestTools",
#    "leadUserName": u"fanwei",
#    "assigneeType": "COMPONENT_LEAD",
#    "isAssigneeTypeValid": False,
#    "project": None,
#}

com_template = {
    "name": u"D-多媒体",
    "leadUserName": u"liuzh",
    "assigneeType": "COMPONENT_LEAD",
    "isAssigneeTypeValid": False,
    "project": None,
}

create_com_url = jira_server_url + '/rest/api/2/component'
for project in project_keys:
    com_template['project'] = project
    print com_template
for project in project_keys:
    com_template['project'] = project
    content = json.dumps(com_template)
    resp, content = client.request(method="POST", uri=create_com_url, headers=headers, body=content)
    if resp['status'] != '201':
        errmsg = 'Create comp ' + com_template['name'] + " Failed!!"
        print errmsg
