#!/usr/bin/env python
# -*- coding: utf-8 -*-
import base64
import urlparse
import json
from tlslite.utils import keyfactory
import oauth2 as oauth


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

project_keys.remove('TEMP')
project_keys.remove('TRANSTOOL')
project_keys.remove('TESTTOOLS')

project_keys

com_dirs = []
for project in project_keys:
    com_project_url = mother_project_url + '/' + project + '/components'
    resp, com = client.request(com_project_url, "GET")
    com_dirs.append(json.loads(com))

assert(len(com_dirs) == len(project_keys))

need_update_sw_id = []
for coms_project in com_dirs:
    for com in coms_project:
        #if com['name'] == u'L-录屏' or com['name'] == u'C-长截屏':
        if com['name'] == u'S-三方应用':
            need_update_sw_id.append(com['id'])

len(need_update_sw_id)

update_com_content = json.dumps({"leadUserName": u"tianliang"})
#update_com_content = json.dumps({'name': u'S-SystemUI'})
jira_server_url = "http://bug.chenyee.com:8080"
for sw_id in need_update_sw_id:
    update_com_url = jira_server_url + "/rest/api/2/component/" + sw_id
    resp, content = client.request(method="PUT", uri=update_com_url, headers=headers, body=update_com_content)
    print resp['status']





#update catalog project
'''
list(df[df[u'源头负责人'] == u'冯佩佩']['项目'])
list(df[df[u'源头负责人'] == u'田亮']['项目'])
list(df[df[u'源头负责人'] == u'唐超磊']['项目'])
fengpeipei = list(df[df[u'源头负责人'] == u'冯佩佩']['项目'])
tianliang = list(df[df[u'源头负责人'] == u'田亮']['项目'])
tangchaolei = list(df[df[u'源头负责人'] == u'唐超磊']['项目'])
project_keys
for project in project_keys:
    if project[0:7] in tangchaolei:
        print(project)
tangchaolei
project_cata = {}
project_cata = {'fengpeipei':[], 'tianliang':[], 'tangchaolei':[]}
for project in project_keys:
    if project[0:7] in tangchaolei:
        project_cata['tangchaolei'].append(project)
    if project[0:7] in fengpeipei:
        project_cata['fengpeipei'].append(project)
    if project[0:7] in tianliang:
        project_cata['tianliang'].append(project)
project_cata
project_cata = {u'fengpeipei':[], u'tianliang':[], u'tangchaolei':[]}
for project in project_keys:
    if project[0:7] in tangchaolei:
        project_cata['utangchaolei'].append(project)
    if project[0:7] in fengpeipei:
        project_cata['ufengpeipei'].append(project)
    if project[0:7] in tianliang:
        project_cata[u'tianliang'].append(project)
for project in project_keys:
    if project[0:7] in tangchaolei:
        project_cata[u'tangchaolei'].append(project)
    if project[0:7] in fengpeipei:
        project_cata[u'fengpeipei'].append(project)
    if project[0:7] in tianliang:
        project_cata[u'tianliang'].append(project)
project_cata
com_dirs = []
for project in project_cata[u'tianliang']:
    com_project_url = mother_project_url + '/' + project + '/components'
    resp, com = client.request(com_project_url, "GET")
    com_dirs.append(json.loads(com))
com_dirs
need_update_sw_id = []
for coms_project in com_dirs:
    for com in coms_project:
        #if com['name'] == u'L-录屏' or com['name'] == u'C-长截屏':
        if com['name'] == u'S-三方应用':
            need_update_sw_id.append(com['id'])
need_update_sw_id
update_com_content = json.dumps({"leadUserName": u"tianliang"})
#update_com_content = json.dumps({'name': u'S-SystemUI'})
jira_server_url = "http://bug.chenyee.com:8080"
for sw_id in need_update_sw_id:
    update_com_url = jira_server_url + "/rest/api/2/component/" + sw_id
    resp, content = client.request(method="PUT", uri=update_com_url, headers=headers, body=update_com_content)
    print resp['status']
project_cata
com_dirs = []
for project in project_cata[u'fengpeipei']:
    com_project_url = mother_project_url + '/' + project + '/components'
    resp, com = client.request(com_project_url, "GET")
    com_dirs.append(json.loads(com))
need_update_sw_id = []
for coms_project in com_dirs:
    for com in coms_project:
        #if com['name'] == u'L-录屏' or com['name'] == u'C-长截屏':
        if com['name'] == u'S-三方应用':
            need_update_sw_id.append(com['id'])
update_com_content = json.dumps({"leadUserName": u"fengpeipei"})
#update_com_content = json.dumps({'name': u'S-SystemUI'})
jira_server_url = "http://bug.chenyee.com:8080"
for sw_id in need_update_sw_id:
    update_com_url = jira_server_url + "/rest/api/2/component/" + sw_id
    resp, content = client.request(method="PUT", uri=update_com_url, headers=headers, body=update_com_content)
    print resp['status']
com_dirs = []
for project in project_cata[u'tangchaolei']:
    com_project_url = mother_project_url + '/' + project + '/components'
    resp, com = client.request(com_project_url, "GET")
    com_dirs.append(json.loads(com))
need_update_sw_id = []
for coms_project in com_dirs:
    for com in coms_project:
        #if com['name'] == u'L-录屏' or com['name'] == u'C-长截屏':
        if com['name'] == u'S-三方应用':
            need_update_sw_id.append(com['id'])
update_com_content = json.dumps({"leadUserName": u"tangchaolei"})
#update_com_content = json.dumps({'name': u'S-SystemUI'})
jira_server_url = "http://bug.chenyee.com:8080"
for sw_id in need_update_sw_id:
    update_com_url = jira_server_url + "/rest/api/2/component/" + sw_id
    resp, content = client.request(method="PUT", uri=update_com_url, headers=headers, body=update_com_content)
    print resp['status']
'''