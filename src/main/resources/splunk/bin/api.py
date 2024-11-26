from splunk.persistconn.application import PersistentServerConnectionApplication
import json
import logging
import requests
import sys
import os
from urllib.parse import quote_plus

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import splunklib.client as client

class index(PersistentServerConnectionApplication):
    APP_NAME = "hibp"

    def __init__(self, command_line, command_arg, logger=None):
        super(PersistentServerConnectionApplication, self).__init__()
        logging.basicConfig(level=logging.INFO) 
        self.logger = logger
        if self.logger == None:
            self.logger = logging.getLogger(f"splunk.appserver.{self.APP_NAME}")
            
    def get_proxy_config(self, config, service):
        proxyUser=""
        proxyPass=""
        proxyHost=config['proxyServer']
        proxyPort=config['proxyPort']
        latestPass=0
        if(int(config['authenticationEnabled']) == 1):
            proxyUser=config['proxyUsername']
            for password in service.storage_passwords.list():
                if(password.content.realm == "hibp-proxy"):
                    if(int(password.content.username) >= latestPass):
                        latestPass=int(password.content.username)
                        proxyPass=password.content.clear_password
                        self.logger.info(proxyPass)
            proxyauth = 'http://{user}:{passw}@{proxy}:{port}'.format(user=quote_plus(proxyUser),
                                                                      passw=quote_plus(proxyPass),
                                                                      proxy=proxyHost,
                                                                      port=proxyPort)
            return {'http': proxyauth, 'https': proxyauth }
        else:
            proxynoauth = 'http://{proxy}:{port}'.format(proxy=proxyHost,
                                                         port=proxyPort)
            return {'http': proxynoauth, 'https': proxynoauth }

    def handle(self, in_string):
        args = json.loads(in_string)
        if args["method"] != "POST":
            return {"payload": "", "status": 504}
        
        service = client.connect(token=args['session']['authtoken'], app=self.APP_NAME)
        inputs_conf = service.confs['inputs']['hibp_domainsearch://default'].content
        proxyconf = {}
        if int(inputs_conf['proxyEnabled']) == 1:
            proxyconf=self.get_proxy_config(inputs_conf, service)

        form = dict(args.get("form", []))
        try:
            APIKEY = form["apikey"]
        except KeyError:
            return {"payload": "No apikey provided", "status": 400}
        
        try:
            ENDPOINT = form["endpoint"]
        except KeyError:
            return {"payload": "No endpoint provided", "status": 400}

        try:
            with requests.get(f"https://haveibeenpwned.com/api/v3/{ENDPOINT}", proxies=proxyconf, headers={"hibp-api-key": APIKEY, "user-agent": "HIBP-Splunk-App"}) as r:
                return {"payload": r.text, "status": r.status_code}
        except Exception as e:
            return {"payload": str(e), "status": 500}
        