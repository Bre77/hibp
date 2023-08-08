from splunk.persistconn.application import PersistentServerConnectionApplication
import json
import logging
import requests

class index(PersistentServerConnectionApplication):
    APP_NAME = "hibp"

    def __init__(self, command_line, command_arg, logger=None):
        self.logger = logger
        if self.logger == None:
            self.logger = logging.getLogger(f"splunk.appserver.{self.APP_NAME}")

        PersistentServerConnectionApplication.__init__(self)

    def handle(self, in_string):
        args = json.loads(in_string)
        if args["method"] != "POST":
            return {"payload": "", "status": 504}

        if not (APIKEY := args.get("apikey")):
            return {"payload": "No apikey provided", "status": 400}
        
        if not (ENDPOINT := args.get("endpoint")):
            return {"payload": "No endpoint provided", "status": 400}

        with requests.get(f"https://haveibeenpwned.com/api/v3/{ENDPOINT}", headers={"hibp-api-key": APIKEY, "user-agent": "HIBP-Splunk-App"}) as r:
            return {"payload": r.text, "status": r.status_code}