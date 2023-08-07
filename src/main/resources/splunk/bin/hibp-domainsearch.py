from splunk.rest import simpleRequest
import json
import sys
import os
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common


class configs(common.RestHandler):
    # MAIN HANDLE
    def handle(self, in_string):
        args = self.getArgs(in_string)

        # Crash for debugging
        if args.get("path_info") == "crash":
            raise Exception("CRASH")

        # Ensure server is specified, as its required by every method here
        if "server" not in args["query"]:
            return self.json_error("Missing required field", 400, str(e), 400)

        # Get the relevant uri and token for the server specified
        if args["query"]["server"] == "local":
            uri = self.LOCAL_URI
            token = self.AUTHTOKEN
        else:
            uri = f"https://{self.hostport(args['query']['server'])}"
            token = self.gettoken(args["query"]["server"])
        if type(token) is dict:
            return token

        if args["method"] == "POST":
            try:
                [server, file, user, app, stanza] = self.getInput(
                    args, ["server", "file", "user", "app", "stanza"]
                )
            except Exception as e:
                return self.json_error(
                    "Missing one of the required fields: server, file, user, app, stanza",
                    "Internal",
                    str(e),
                    400,
                )

            stanza = urllib.parse.quote(stanza, safe="")

            try:
                resp, content = simpleRequest(
                    f"{uri}/servicesNS/{user}/{app}/configs/conf-{file}/{stanza}/acl?output_mode=json",
                    sessionKey=token,
                    postargs=args["form"],
                )
                if resp.status != 200:
                    return self.json_error(
                        f"Changing ACL of {stanza} on {server} returned {resp.status}",
                        resp.status,
                        json.loads(content)["messages"][0]["text"],
                    )
                s = json.loads(content)["entry"][0]
            except Exception as e:
                return self.json_error(
                    f"POST request to {uri}/servicesNS/{user}/{app}/configs/conf-{file}/{stanza}/acl failed",
                    e.__class__.__name__,
                    str(e),
                )
            return self.json_response(
                {
                    "sharing": s["acl"]["sharing"],
                    "owner": s["acl"]["owner"],
                    "write": [0, 1][s["acl"]["can_write"]],
                    "change": [0, 1][s["acl"]["can_change_perms"]],
                    "readers": s["acl"]["perms"].get("read", [])
                    if s["acl"]["perms"]
                    else [],
                    "writers": s["acl"]["perms"].get("write", [])
                    if s["acl"]["perms"]
                    else [],
                    "share": [
                        [0, 1][s["acl"]["can_share_global"]],
                        [0, 1][s["acl"]["can_share_app"]],
                        [0, 1][s["acl"]["can_share_user"]],
                    ],
                },
                201,
            )

        return self.json_error("Method Not Allowed", 405)
