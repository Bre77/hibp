from splunk.persistconn.application import PersistentServerConnectionApplication
import json
import logging
from splunk.rest import simpleRequest

class index(PersistentServerConnectionApplication):
    APP_NAME = "hibp"

    def __init__(self, command_line, command_arg, logger=None):
        self.logger = logger
        if self.logger == None:
            self.logger = logging.getLogger(f"splunk.appserver.{self.APP_NAME}")

        PersistentServerConnectionApplication.__init__(self)

    def handle(self, in_string):
        args = json.loads(in_string)
        LOCAL_URI = args["server"]["rest_uri"]
        AUTHTOKEN = args["session"]["authtoken"]

        if args["method"] == "POST":
            form = dict(args.get("form", []))

            try:
                INDEX = form["index"]
            except KeyError:
                return {"payload": "No index provided", "status": 400}
            

            try:
                if(INDEX is not ""):
                    self.logger.info("HIBP Input Manager: Setting index")
                    simpleRequest(
                        f"{LOCAL_URI}/servicesNS/nobody/{self.APP_NAME}/properties/inputs/hibp_domainsearch%3A%2F%2Fdefault",
                        sessionKey=AUTHTOKEN,
                        method="POST",
                        postargs={"index": INDEX},
                        raiseAllErrors=True,
                    )
                    self.logger.info("HIBP Input Manager: Enabling input")
                    simpleRequest(
                        f"{LOCAL_URI}/servicesNS/nobody/{self.APP_NAME}/data/inputs/hibp_domainsearch/default/enable",
                        sessionKey=AUTHTOKEN,
                        method="POST",
                        raiseAllErrors=True,
                    )
                    self.logger.info("HIBP Input Manager: Updating macro")
                    simpleRequest(
                        f"{LOCAL_URI}/servicesNS/nobody/{self.APP_NAME}/configs/conf-macros/hibp_index",
                        sessionKey=AUTHTOKEN,
                        method="POST",
                        postargs={"definition": f"index={INDEX}"},
                        raiseAllErrors=False,
                    )
                    self.logger.info("HIBP Input Manager: Marking as configured")
                    simpleRequest(
                        f"{LOCAL_URI}/servicesNS/nobody/{self.APP_NAME}/apps/local/hibp",
                        sessionKey=AUTHTOKEN,
                        method="POST",
                        postargs={"configured": "1"},
                        raiseAllErrors=False,
                    )
                else:
                    self.logger.info("HIBP Input Manager: Disabling input")
                    simpleRequest(
                        f"{LOCAL_URI}/servicesNS/nobody/{self.APP_NAME}/data/inputs/hibp_domainsearch/default/disable",
                        sessionKey=AUTHTOKEN,
                        method="POST",
                        raiseAllErrors=True,
                    )

                return {"payload": "", "status": 200}
            except Exception as e:
                return {"payload": str(e), "status": 500}
            
        elif args['method'] == "DELETE":
            try:
                # Remove all entries from hibp-pwned collection
                self.logger.info("HIBP Reset: Removing all entries from hibp-pwned")
                simpleRequest(
                    f"{LOCAL_URI}/servicesNS/nobody/{self.APP_NAME}/collections/data/hibp-pwned",
                    sessionKey=AUTHTOKEN,
                    method="DELETE",
                    raiseAllErrors=True,
                )
                self.logger.info("HIBP Reset: Disabling input")
                simpleRequest(
                    f"{LOCAL_URI}/servicesNS/nobody/{self.APP_NAME}/data/inputs/hibp_domainsearch/default/disable",
                    sessionKey=AUTHTOKEN,
                    method="POST",
                    raiseAllErrors=True,
                )
                self.logger.info("HIBP Reset: Enabling input")
                simpleRequest(
                    f"{LOCAL_URI}/servicesNS/nobody/{self.APP_NAME}/data/inputs/hibp_domainsearch/default/enable",
                    sessionKey=AUTHTOKEN,
                    method="POST",
                    raiseAllErrors=True,
                )

                return {"payload": "", "status": 200}
            except Exception as e:
                return {"payload": str(e), "status": 500}
            
        else:
            return {"payload": "", "status": 504}
        