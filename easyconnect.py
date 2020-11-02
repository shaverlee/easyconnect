
# -*-coding: utf-8 -*-

import requests
import http.client
import xml.etree.ElementTree as ET
import json
import hashlib
import logging
logging.basicConfig()
log = logging.getLogger("requests.packages.urllib3")
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)
http.client.HTTPConnection.debuglevel = 1

########################
# 输入你的SSL VPN连接信息 #
########################
dest_url = ''
user = ''
password = ''

lang = 'en_US'
user_agent = 'EasyConnect_Linux_Ubuntu'


def request_wrapper(func):
    def f(url, **kargs):
        log.debug('request url=%s', url)
        r = func(url, verify=False, **kargs)
        log.debug('response = %s', r.text)
        return r

    return f


requests.get = request_wrapper(requests.get)
requests.post = request_wrapper(requests.post)


def web_handler():
    r = requests.get(dest_url)
    return r.status_code == requests.codes.ok


def XML(s):
    root = ET.fromstring(s)

    def value_of(name):
        r = [ch for ch in root if ch.tag == name]
        if r:
            return r[0].text

    return value_of


class ECAgent:
    def __init__(self, host='127.0.0.1', port=54530,
                 protocol='https', id='ECAgent'):
        self._prefix = '%s://%s:%d/%s' % (protocol, host, port, id)
        self._token = ''
        self._auth_dict = {}
        self._cookie = {'language': lang}
        # self.__initECAgent()

    def login_auth(self):
        paths = {
            'csrf_rand_code': 'CSRF_RAND_CODE',
            'twfid': 'TwfID',
            'rsa_encrypt_key': 'RSA_ENCRYPT_KEY',
            'rsa_encrypt_exp': 'RSA_ENCRYPT_EXP',
        }
        r = requests.get(
            '%s/por/login_auth.csp?apiversion=1' % dest_url,
            cookies=self._cookie,
            headers={'user-agent': user_agent},
        )
        xml = XML(r.content)
        self._auth_dict = dict([(k, xml(v))
                                for k, v in paths.items()])
        self._cookie['TWFID'] = xml('TwfID')
        self.refresh_token()
        return self._auth_dict

    def login_psw(self):
        def encrypt_psw(psw):
            psw += '_' + self._auth_dict['csrf_rand_code']
            key = self._auth_dict['rsa_encrypt_key']
            return self.rsa_encrypt(key, psw)

        r = requests.post(
            '%s/por/login_psw.csp?anti_replay=1&encrypt=1&apiversion=1' % dest_url,
            data={
                'mitm_result': '',
                'svpn_req_randcode': self._auth_dict['csrf_rand_code'],
                'svpn_name': user,
                'svpn_password': encrypt_psw(password),
                'svpn_rand_code': '',
            },
            headers={'user-agent': user_agent},
            cookies=self._cookie,
        )
        xml = XML(r.content)
        if xml('Result') == "1":
            self._auth_dict['twfid'] = xml('TwfID')
            self._cookie['TWFID'] = xml('TwfID')
            self.refresh_token()
            return True

    def init_ec_agent(self):
        ret = self.request('InitEcAgent',
                           arg1='%s%%20%d' % (dest_url[8:], 443))
        return ret['result'] == '1'

    def detect_ec_agent(self):
        self.request('DetectECAgent')

    def select_line(self):
        ret = self.request('SelectLines', arg1=dest_url)
        return ret['result'] == '1'

    def check_proxy_setting(self):
        ret = self.request('CheckProxySetting')
        return True # ret['result'] == '1'

    def update_controls(self, arg):
        ret = self.request('UpdateControls', arg1=arg)
        return ret['result'] == '1'

    def get_encrypt_key(self):
        ret = self.request('GetEncryptKey')
        self.encrypt_key = ret['result']
        return ret['result']

    def check_relogin(self):
        ret = self.request('CheckReLogin', arg1=self.make_relogin_id())
        return ret['result'] == '1'

    def do_query_service(self, arg):
        ret = self.request('DoQueryService',
                           arg1=arg)
        if ret['result'] == '1':
            return ret['data']
        return len(ret['result'])

    def query_hardid(self):
        ret = self.do_query_service('QUERY GETHARDID')
        if ret:
            cookie_map = {
                'SSL_REMOTE_HOST': 'hostName',
                'SSL_REMOTE_MAC': 'macAddress',
            }
            for k, v in cookie_map.items():
                self._cookie[k] = ret[v]
            return True

    def query_qstate(self):
        def do_a_query():
            ret = self.do_query_service('QUERY QSTATE ALLSERVICES')
            return all([v in ['18', '43'] for v in ret.values()])

        for i in range(60):
            if do_a_query():
                return True
            import time
            time.sleep(0.5)

    def query_login_status(self):
        ret = self.do_query_service('QUERY LOGINSTATUS')
        return ret['status'] == 1

    def query_display_msg(self):
        self.do_query_service('QUERY DISPLAYMSG')
        
    def get_config(self, index):
        ret = self.request('GetConfig', arg1=str(index))
        if ret['result'] == '1':
            if index == 1:
                self.svpn_id = ret['data']['Conf']['Service']['SvpnID']
            return ret['data']

    def do_configure(self, arg):
        ret = self.request('DoConfigure', arg1=arg)
        return ret['result'] == '1'

    def do_xml_configure(self, arg):
        ret = self.request('DoXmlConfigure', arg1=arg)
        return ret['result'] == '1'

    def set_lang(self):
        return self.do_configure('SET LANG %s' % lang)

    def set_twfid(self):
        twfid = self.make_relogin_id()  # ???
        return self.do_configure('SET TWFID %s' % twfid)

    def set_server_addr(self):
        return self.do_configure('SET SERVADDR %s %d' % (dest_url[8:], 443))

    def set_login_addr(self):
        return self.do_configure('SET LOGINADDR %s' % dest_url)

    def set_browser_type(self):
        return self.do_configure('SET BROWSER %s' % 'default')

    def start_service(self):
        ret = self.request('StartService')
        return ret['result'] == '1'

    def setter(self, arg1, arg2, arg3):
        ret = self.request('Setter', arg1=arg1, arg2=arg2, arg3=arg3)
        return ret['result'] == '1'

    def request(self, op, type='EC', **kargs):
        if not hasattr(self, 'cbnum'):
            self.cbnum = 0
        self.cbnum += 1
        args = [('op', op)] + list(kargs.items()) + [
            ('type', type),
            ('token', self._token),
            ('callBack', 'cb%5d' % (10000 + self.cbnum)),
        ]
        response = requests.get(
            '%s?%s' % (self._prefix,
                       '&'.join(['%s=%s' % kv for kv in args])),
            headers={'user-agent': user_agent},
        )
        return json.loads(response.text[8:-1])

    def refresh_token(self):
        md5_salt = '__md5_salt_for_ecagent_session__'
        self._token = hashlib.md5(
            (self._auth_dict['twfid'] + md5_salt).encode()
        ).hexdigest()

    def rsa_encrypt(self, key, msg):
        from Crypto.Cipher import PKCS1_v1_5 as PKCS1
        from Crypto.PublicKey import RSA
        from binascii import unhexlify, hexlify

        exp = self._auth_dict['rsa_encrypt_exp'] or '65537'
        key = RSA.construct((
            int.from_bytes(unhexlify(key), byteorder='big'),
            int(exp)))

        def my_hex(bs):
            return hexlify(bs).decode()  # ''.join(['%02x' % c for c in bs])
        return my_hex(PKCS1.new(key).encrypt(msg.encode()))

    def make_relogin_id(self):
        key = self.encrypt_key
        return self.rsa_encrypt(key, self._auth_dict['twfid'])

    def logout(self):
        ret = self.request('Logout')
        return ret['result'] == "1"


agent = None


def start():
    # web_handler()
    global agent
    if agent:
        return
    agent = ECAgent()

    agent.detect_ec_agent()
    if agent.select_line() and \
       agent.init_ec_agent() and \
       agent.check_proxy_setting() and \
       agent.update_controls('BEFORELOGIN') and \
       agent.do_query_service('QUERY CONTROLS UPDATEPROCESS'):
        agent.login_auth()
        if agent.init_ec_agent() and \
           agent.set_lang():
            agent.get_encrypt_key()
            if agent.check_relogin() and \
               agent.check_proxy_setting():
                agent.query_hardid()

                agent.get_encrypt_key()
                if agent.set_lang() and \
                   agent.check_relogin() and \
                   agent.init_ec_agent():
                    agent.login_auth()
                    if agent.login_psw():
                        agent.get_encrypt_key()
                        if agent.check_relogin():
                            agent.get_encrypt_key()
                            agent.set_twfid()
                            configs = [agent.get_config(i+1)
                                       for i in range(2)]
                            if agent.check_proxy_setting() and \
                               agent.set_server_addr() and \
                               all([agent.do_xml_configure(i+1)
                                    for i in range(2)]):
                                if agent.start_service() and \
                                   agent.setter('sfjssdk',
                                             json.dumps({
                                                 'loginClientType': 2,
                                                 'port': 54530,
                                                 'vpnURL': dest_url,
                                                 'fromURL': dest_url,
                                                 'browserType': 'default',
                                                 'loginName': user,
                                                 'trayType': 1,
                                                 'lang': 'en_US',
                                                 'securityCheck': False,
                                                 'strategies': [],
                                             }),
                                             '0'):
                                    agent.query_qstate()
                                    agent.set_browser_type()
                                    agent.set_login_addr()
                                    agent.set_server_addr()
                                    agent.setter('sfjssdklocal',
                                              json.dumps({
                                                  'enableAutoLogin': 1,
                                                  'enableSavePwd': 1,
                                                  'svpnID': agent.svpn_id,
                                                  'hasTcpResource': 0,
                                                  'hasRemoteApp': 0,
                                                  'enableHtp': 0,
                                                  'enableScache': 0,
                                                  'enableWebOpt': 0,
                                                  'webOptDevice': 0,
                                                  'showRc': 1,
                                              }),
                                              '0')
                                    agent.query_login_status()
                                    agent.query_display_msg()


def stop():
    global agent
    if agent:
        agent.logout()
        agent = None


if __name__ == '__main__':
    start()
