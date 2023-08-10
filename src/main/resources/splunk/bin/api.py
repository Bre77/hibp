from splunk.persistconn.application import PersistentServerConnectionApplication
import json
import logging
import requests
import time

class index(PersistentServerConnectionApplication):
    APP_NAME = "hibp"

    def __init__(self, command_line, command_arg, logger=None):
        self.logger = logger
        if self.logger == None:
            self.logger = logging.getLogger(f"splunk.appserver.{self.APP_NAME}")

        PersistentServerConnectionApplication.__init__(self)

    def RetryRequest(self, url, headers):
        while True:
            with requests.get(url, headers=headers) as r:
                if r.status_code == 429:
                    wait = int(r.headers['retry-after'])+1
                    if wait > 11:
                        return r
                else:
                    return r
            time.sleep(wait)

    def handle(self, in_string):
        args = json.loads(in_string)
        if args["method"] != "POST":
            return {"payload": "", "status": 504}

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
            r = self.RetryRequest(f"https://haveibeenpwned.com/api/v3/{ENDPOINT}", {"hibp-api-key": APIKEY, "user-agent": "HIBP-Splunk-App"})
            return {"payload": r.text, "status": r.status_code}
        except Exception as e:
            return {"payload": str(e), "status": 500}
        