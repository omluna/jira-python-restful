mport base64
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

        with open('/Users/mmuunn/Documents/Works/jira-python-restful/oauth_key/mykey.pem', 'r') as f:
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
projects_dir
for project in projects_dir:
    print project['key']
resp, projects = client.request(mother_project_url, "GET")
projects_dir = json.loads(projects)
projects_dir
project_keys = []
for project in projects_dir:
    print project['key']
    project_keys.append(project['key'])
project_keys
project_keys.remove('TEMP')
project_keys.remove('TEST')
project_keys.remove('TRANSTOOL')
project_keys
for project in project_keys:
    com_project_url = mother_project_url + '/' + project + '/components'
    resp, com = client.request(com_project_url, "GET")
    com_dirs.append(json.loads(com))

com_dirs = []
for project in project_keys:
    com_project_url = mother_project_url + '/' + project + '/components'
    resp, com = client.request(com_project_url, "GET")
    com_dirs.append(json.loads(com))

com_dirs
len(com_dirs)
len(project_keys)

need_update_sw_id = []
for coms_project in com_dirs:
    for com in coms_project:
        if com['name'] == u'L-蓝牙' or com['name'] == u'O-OTA':
            need_update_sw_id.append(com['id'])

need_update_sw_id
len(need_update_sw_id)
update_com_content = json.dumps({'leadUserName': u'xuyongji'})
jira_server_url = "http://bug.chenyee.com:8080"
for sw_id in need_update_sw_id:
    update_com_url = jira_server_url + "/rest/api/2/component/" + sw_id
    resp, content = client.request(method="PUT", uri=update_com_url, headers=headers, body=update_com_content)
    print resp['status']
