import os
import sys
import json
import time
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.modularinput import Script, Scheme, Event, EventWriter

class Input(Script):
    APP = "hibp"

    def get_scheme(self):
        scheme = Scheme("HIBP Domain Search")
        scheme.description = "Configure the Have I Been Pwned Domain Search input using the apps setup page at /app/hibp/setup."
        scheme.use_external_validation = False
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        return scheme
    
    def update_lookup(self, ew, latestbreach):
        # Check if latest recorded breach has changed
        checkpointfile = os.path.join(self._input_definition.metadata["checkpoint_dir"],"lastestbreach")
        try:
            with open(checkpointfile, "r") as f:
                if latestbreach == f.read():
                    ew.log(EventWriter.INFO, f"Latest breach hasnt changed from {latestbreach}, will not update breaches lookup")
                    return
        except:
            ew.log(EventWriter.INFO, f"Latest breach has never been checked, will update breaches lookup")
        
        # Get all breaches
        with requests.get("https://haveibeenpwned.com/api/v3/breaches") as r:
            if not r.ok:
                ew.log(EventWriter.ERROR, f"https://haveibeenpwned.com/api/v3/breaches returned {r.status_code}")
                return
            breaches = r.json()
        
        # Update KVstore Collection
        collection = self.service.kvstore["hibp-breaches"]
        for breach in breaches:
            key = breach['Name']
            try:
                collection.data.update(key, breach)
            except:
                breach['_key'] = key
                collection.data.insert(breach)

        with open(checkpointfile, "w") as f:
            f.write(latestbreach)

    #def RetryRequest(self, ew, session, url ):
    #    while True:
    #        with session.get(url) as r:
    #            if r.status_code == 429:
    #                wait = int(r.headers['retry-after'])+1
    #                if wait > 11:
    #                    ew.log(EventWriter.ERROR, f"Wait time {wait}s is too long, will not retry {url}")
    #                    return r
    #            else:
    #                return r
    #        ew.log(EventWriter.INFO, f"Waiting {wait}s before retrying {url}")
    #        time.sleep(wait)

    def stream_events(self, inputs, ew):
        self.service.namespace["app"] = self.APP

        # Request latest breach
        with requests.get("https://haveibeenpwned.com/api/v3/latestbreach") as r:
            if not r.ok:
                ew.log(EventWriter.ERROR, f"https://haveibeenpwned.com/api/v3/latestbreach returned {r.status_code}")
                return
            latestbreach = r.json()['Name']

        # Update CSV Lookup
        self.update_lookup(ew, latestbreach)
        
        ew.log(EventWriter.DEBUG, "Getting API Keys")
        # Check API Key and domains
        apikeys = [
            x.clear_password
            for x in self.service.storage_passwords
            if x.realm == "hibp"
        ]

        for apikey in apikeys:
            with requests.Session() as s:
                s.headers.update({"hibp-api-key": apikey, "user-agent": "HIBP-Splunk-App"})

                # Get all domains
                url1 = "https://haveibeenpwned.com/api/v3/subscribeddomains"
                with s.get(url1) as r1:
                    if not r1.ok:
                        ew.log(EventWriter.ERROR, f"{url1} returned {r1.status_code}")
                        continue
                    domains = r1.json()

                for d in domains:
                    ew.write_event(
                        Event(
                            source=url1,
                            sourcetype=f"hibp:domain",
                            data=json.dumps(d),
                            unbroken=False
                        )
                    )

                    domain = d["DomainName"]

                    # Get Domains Checkpoint
                    checkpointfile = os.path.join(self._input_definition.metadata["checkpoint_dir"],domain)
                    try:
                        with open(checkpointfile, "r") as f:
                            if latestbreach == f.read():
                                #No new breaches for this domain
                                continue
                    except:
                        pass

                    # Get all breached emails in domain
                    url2 = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
                    with s.get(url2) as r2:
                        if r2.status_code == 404:
                            domainsearch = {}
                        elif not r2.ok:
                            ew.log(EventWriter.ERROR, f"{url2} returned {r2.status_code}")
                            continue
                        else:
                            domainsearch = r2.json()

                    ew.log(EventWriter.INFO, f"{domain} has a total of {len(domainsearch)} breached accounts")

                    collection = self.service.kvstore["hibp-pwned"]

                    for alias in domainsearch:
                        breaches = domainsearch[alias]
                        key = f"{alias}@{domain}"

                        # Pull this emails record from KVstore
                        try:
                            pwned = collection.data.query_by_id(key)
                        except:
                            pwned = None

                        # Find only new breaches by comparing API with KVstore
                        newbreaches = [breach for breach in breaches if breach not in pwned['Breaches']] if pwned else breaches

                        if newbreaches:
                            # Write event for each new breach
                            for breach in newbreaches:
                                ew.write_event(
                                    Event(
                                        source=url2,
                                        sourcetype=f"hibp:pwned",
                                        data=f"{alias}@{domain} {breach}",
                                        unbroken=False,
                                    )
                                )
                            # Update or insert KVstore for this email 
                            if pwned:
                                collection.data.update(key,{"Breaches": breaches})
                            else:
                                collection.data.insert({"_key": key, "Breaches":  breaches})
                            
                    # Record checkpoint for this domain
                    with open(checkpointfile, "w") as f:
                        f.write(latestbreach)

if __name__ == "__main__":
    exitcode = Input().run(sys.argv)
    sys.exit(exitcode)
