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

        with open('/Users/mmuunn/Documents/Works/Jira Bug/jira-python-restful/oauth_key/mykey.pem', 'r') as f:
            data = f.read()
        privateKeyString = data.strip()

        privatekey = keyfactory.parsePrivateKey(privateKeyString)
        signature = privatekey.hashAndSign(raw)

        return base64.b64encode(signature)


def create_component(project_key, com_list, client):
    # create component
    com_template = {
        "name": u"a",
        "leadUserName": u"a",
        "assigneeType": "COMPONENT_LEAD",
        "isAssigneeTypeValid": False,
        "project": project_key,
    }

    create_com_url = jira_server_url + '/rest/api/2/component'
    for com in com_list:
        # print "create component:" + com['name']
        com_template['name'] = com['name']
        if com['isAssigneeTypeValid'] and 'lead' in com:
            com_template['leadUserName'] = com['lead']['key']
            com_template['isAssigneeTypeValid'] = True
        else:
            com_template['leadUserName'] = u''
            com_template['isAssigneeTypeValid'] = False
        # com_templates.append(com_template)
        content = json.dumps(com_template)
        resp, content = client.request(method="POST", uri=create_com_url, headers=headers, body=content)
        if resp['status'] != '201':
            errmsg = 'Create comp ' + com_template['name'] + " Failed!!"
            print errmsg
    print "Finish creating component!!"


def create_project(project_key, from_project_info, client):
    # use jira workround api to create project with the same set of schemes
    create_project_info = {
        'key': project_key,
        'lead': from_project_info['lead']['key'],
        'name': project_key,
    }

    # create project
    project_content = json.dumps(create_project_info)
    create_project_url = jira_server_url + '/rest/project-templates/1.0/createshared/' + from_project_info['id']
    resp, content = client.request(method="POST", uri=create_project_url, headers=headers, body=project_content)

    if resp['status'] != '200':
        errmsg = 'Create project ' + project_key + " Failed!!"
        raise Exception(errmsg + "\n" + content)
    print "Finish creating project scheme, now starting create comoponent...."

    create_component(project_key, from_project_info['com_list'], client)
    print "New project:" + project_key + " is ready!"


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

    from_project_key = orig_args[0]
    from_project_url = jira_server_url + "/rest/api/2/project/" + from_project_key

    project_keys = orig_args[1]
    print project_keys
    project_list = project_keys.split(',')

    resp, content = client.request(from_project_url, "GET")
    if resp['status'] != '200':
        errmsg = 'Cloned project ' + from_project_key + " is not exist"
        raise Exception(errmsg)

    from_project_info = json.loads(content)

    # get componment
    get_com_url = jira_server_url + '/rest/api/2/project/' + from_project_key + '/components'
    resp, content = client.request(get_com_url, "GET")
    if resp['status'] != '200':
        errmsg = 'Get components from the project ' + from_project_key + " Failed!!"
        raise Exception(errmsg + "\n" + content)

    coms = json.loads(content)
    from_project_info['com_list'] = coms

    for project_key in project_list:
        create_project(project_key, from_project_info, client)


if __name__ == '__main__':
    main(sys.argv[1:])
