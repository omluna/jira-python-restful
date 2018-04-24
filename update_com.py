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
access_token = {'oauth_token': 'QHnpXBfHjXhYKfTMVDLMTyInQCefANgv',
                'oauth_token_secret': 'k20W95a4ncIhSwBAcvlrXsIQn1IlZzcK'}
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
    print(project['key'])
    project_keys.append(project['key'])

project_keys.remove('TEMP')
project_keys.remove('TRANSTOOL')
project_keys.remove('TESTTOOLS')
project_keys.remove('SCLUB')
project_keys.remove('OA')
project_keys.remove('DSHOP')
#project_keys = ['CSW1703CTA']

com_dirs = []
for project in project_keys:
    com_project_url = mother_project_url + '/' + project + '/components'
    resp, com = client.request(com_project_url, "GET")
    com_dirs.append(json.loads(com))

assert(len(com_dirs) == len(project_keys))

CTA1703_com = [
    u'B-便签',
    u'B-拨号盘',
    u'C-出国助手',
    u'C-长截屏',
    u'D-动态壁纸',
    u'D-定时开关机',
    u'D-电子邮件',
    u'D-短信销统',
    u'E-儿童模式',
    u'F-Framework',
    u'F-访客模式',
    u'G-GMS',
    u'H-HotKnot',
    u'H-黑屏手势',
    u'J-截屏',
    u'J-计算器',
    u'K-开关机',
    u'K-控制中心',
    u'L-录屏',
    u'L-录音机',
    u'L-浏览器',
    u'L-联系人',
    u'L-蓝牙',
    u'L-铃声',
    u'M-密码保护',
    u'O-OTA',
    u'Q-全面屏',
    u'R-人脸解锁',
    u'R-日历',
    u'S-STK',
    u'S-SystemUI',
    u'S-手机防盗',
    u'S-手电筒',
    u'S-搜索',
    u'S-收音机',
    u'S-时钟',
    u'S-私密空间',
    u'S-视频播放器',
    u'S-视频编辑',
    u'S-设置',
    u'S-设置存储',
    u'S-锁屏',
    u'S-随变',
    u'T-图库',
    u'T-天气',
    u'T-抬手亮屏',
    u'T-通知栏',
    u'T-通话',
    u'T-通话记录',
    u'U-U方型互切',
    u'W-WIFI',
    u'W-WIFI直连',
    u'W-文件管理器',
    u'W-无线充电',
    u'X-下载管理',
    u'X-信息',
    u'X-悬浮触点',
    u'X-相机',
    u'X-系统升级',
    u'X-系统备份',
    u'X-系统管家',
    u'X-虚拟手势',
    u'Y-一键换机',
    u'Y-应用分身',
    u'Y-应用安装',
    u'Y-用户中心',
    u'Y-用户反馈',
    u'Y-音乐播放器',
    u'Z-主题公园',
    u'Z-指南针',
    u'Z-桌面主菜单',
]


need_update_sw_id = []
for coms_project in com_dirs:
    for com in coms_project:
        if com['name'] == u'L-录屏' or com['name'] == u'C-长截屏':
            # if com['name'] == u'S-三方应用':
            # if com['name'] == u'S-手电筒' or com['name'] == u'Z-指南针' or com['name'] == u'X-系统备份':
            # if com['name'] in CTA1703_com:
            need_update_sw_id.append(com['id'])

len(need_update_sw_id)

update_com_content = json.dumps({"leadUserName": u"zhaocl"})
#update_com_content = json.dumps({'name': u'S-SystemUI'})
jira_server_url = "http://bug.chenyee.com:8080"
for sw_id in need_update_sw_id:
    update_com_url = jira_server_url + "/rest/api/2/component/" + sw_id
    resp, content = client.request(
        method="PUT", uri=update_com_url, headers=headers, body=update_com_content)
    print resp['status']


# update catalog project
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
