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

        with open('/Users/mmuunn/Documents/Works/jira-python-restful/oauth_key/mykey.pem', 'r') as f:
            data = f.read()
        privateKeyString = data.strip()

        privatekey = keyfactory.parsePrivateKey(privateKeyString)
        signature = privatekey.hashAndSign(raw)

        return base64.b64encode(signature)

consumer_key = 'OauthKey'
consumer_secret = 'dont_care'
consumer = oauth.Consumer(consumer_key, consumer_secret)
data_url = 'http://bug.chenyee.com:8080/rest/api/2/issue/SWW1616A-138'
mother_project_url = 'http://bug.chenyee.com:8080/rest/api/2/project/SW17W04A'

access_token = {'oauth_token': 'QHnpXBfHjXhYKfTMVDLMTyInQCefANgv', 'oauth_token_secret': 'k20W95a4ncIhSwBAcvlrXsIQn1IlZzcK'}
accessToken = oauth.Token(access_token['oauth_token'], access_token[
                          'oauth_token_secret'])
client = oauth.Client(consumer, accessToken)
client.set_signature_method(SignatureMethod_RSA_SHA1())

resp, content = client.request(mother_project_url, "GET")
resp, content = client.request(mother_project_url, "GET")
mother_project_url = 'http://bug.chenyee.com:8080/rest/api/2/project'
resp, content = client.request(mother_project_url, "GET")
headers = {"Content-Type": "application/json"}
resp, content = client.request(method="POST", url=mother_project_url, headers=headers, body=project_info)
resp, content = client.request(method="POST", uri=mother_project_url, headers=headers, body=j)
update_project_info = {"notificationScheme": 10000}
up = json.dumps(update_project_info)
update_project_url = 'http://bug.chenyee.com:8080/rest/api/2/project/TEST'
resp, content = client.request(method="PUT", uri=update_project_url, headers=headers, body=j)
resp, content = client.request(method="PUT", uri=update_project_url, headers=headers, body=up)
update_project_info = {"workflowScheme": 10200}
up = json.dumps(update_project_info)
resp, content = client.request(method="PUT", uri=update_project_url, headers=headers, body=up)
component_url = 'http://bug.chenyee.com:8080/rest/api/2/component/'
mother_project_url
resp, projects = client.request(mother_project_url, "GET")
projects_dir = json.loads(projects)
projects_dir
for project in projects_dir:
    print project['key']
project_keys = []
for project in projects_dir:
    print project['key']
    project_keys.append(project['key'])
project_keys
project_keys.remove('TEMP')
project_keys.remove('TEST')
project_keys
history
mother_project_url
com_project_url = mother_project_url + project_keys[0] + '/components'
com_project_url
com_project_url = mother_project_url + '/' + project_keys[0] + '/components'
com_project_url
resp, com = client.request(com_project_url, "GET")
com_dir = json.loads(com)
com_dir
history
com_dir[0]
com_dir[0]("id")
com_dir[0]["id"]
com_dir[0]["id", "name"]
com_dir[0][("id", "name")]
com_dir[0][["id", "name"]]
com_dir[0].keys()
com_dirs = []
history
for project in project_keys:
    com_project_url = mother_project_url + '/' + project + '/components'
    resp, com = client.request(com_project_url, "GET")
    com_dirs.append(json.loads(com))
len(com_dirs)
len(project_keys)
com_dirs[0][0]
history
jira_server_url = "http://bug.chenyee.com:8080"
update_com_url = jira_server_url + "/rest/api/2/component/"
update_com_content = json.dumps({'name': u'M-MISC(驱动)'})
update_com_content = json.dumps({'name': u'Y-一键换机'})
update_com_content
update_com_url1 = update_com_url + com_dirs[0][0]
update_com_url1 = update_com_url + com_dirs[0][0]('id')
update_com_url1 = update_com_url + com_dirs[0][0]['id']
update_com_url1
update_com_content
resp, content = client.request(method="PUT", uri=update_com_url1, headers=headers, body=update_com_content)
resp
content
com_dirs[0]
com_dirs[1]
history
com_dirs[0][0]
need_update_bsp_id = []
need_update_sw_id = []
for coms_project in com_dirs:
    for com in coms_project:
        if com['name'] == u'M-MISC':
            need_update_sw_id.append(com['id'])
        elif com['name'] == u'A-AAMISC':
            need_update_bsp_id.append(com['id'])
need_update_sw_id
need_update_bsp_id
len(need_update_bsp_id)
len(need_update_sw_id)
need_update_bsp_id[0]
need_update_sw_id[0]
for bsp_id in need_update_bsp_id:
    update_com_url = jira_server_url + "/rest/api/2/component/" + bsp_id
    resp, content = client.request(method="PUT", uri=update_com_url, headers=headers, body=update_com_content)
    print resp['status']
update_com_content = json.dumps({'name': u'M-MISC(软件)'})
for sw_id in need_update_sw_id:
    update_com_url = jira_server_url + "/rest/api/2/component/" + sw_id
    resp, content = client.request(method="PUT", uri=update_com_url, headers=headers, body=update_com_content)
    print resp['status']
