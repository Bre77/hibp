import os
import sys
import csv
import json
import time
import requests
from splunk.rest import simpleRequest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.modularinput import Script, Scheme, Argument, Event, EventWriter

SLEEP = 7

class Input(Script):
    APP = "hibp"

    def get_scheme(self):
        scheme = Scheme("HIBP Domain Search")
        scheme.description = "Retrieves Have I Been Pwned Domain Search data"
        scheme.use_external_validation = False
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = True

        return scheme
    
    def update_lookup(self, ew, latestbreach):
        # Check if latest recorded breach has changed
        path = os.path.join(self._input_definition.metadata["checkpoint_dir"],"lastestbreach")
        try:
            with open(path, "r") as f:
                if latestbreach == f.read():
                    ew.log(EventWriter.INFO, f"Latest breach hasnt changed from {latestbreach}, will not update breaches lookup")
                    return
        except:
            ew.log(EventWriter.DEBUG, f"Latest breach has not ever been checked, will update breaches lookup")
        
        # Get all breaches
        with requests.get("https://haveibeenpwned.com/api/v3/breaches") as r:
            if not r.ok:
                ew.log(EventWriter.ERROR, f"https://haveibeenpwned.com/api/v3/breaches returned {r.status_code}")
                return
            breaches = r.json()

        #Update CSV Lookup
        try:
            with open(os.path.join(os.getenv('SPLUNK_HOME'),"etc","apps",self.APP,"lookups","hibp-breaches.csv"), "w") as f:
                writer = csv.writer(f)
                writer.writerow(["Name","Title","Domain","BreachDate","AddedDate","ModifiedDate","PwnCount","Description","LogoPath","DataClasses","IsVerified","IsFabricated","IsSensitive","IsRetired","IsSpamList","IsMalware"])
                for breach in breaches:
                    writer.writerow([breach["Name"],breach["Title"],breach["Domain"],breach["BreachDate"],breach["AddedDate"],breach["ModifiedDate"],breach["PwnCount"],breach["Description"],breach["LogoPath"],"|".join(breach["DataClasses"]),breach["IsVerified"],breach["IsFabricated"],breach["IsSensitive"],breach["IsRetired"],breach["IsSpamList"],breach["IsMalware"]])
        except Exception as e:
            ew.log(EventWriter.ERROR, f"Failed to update hibp-breaches.csv lookup. {str(e)}")
            return

        with open(path, "w") as f:
            f.write(latestbreach)

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
                with s.get(url1) as r:
                    if not r.ok:
                        ew.log(EventWriter.ERROR, f"{url1} returned {r.status_code}")
                        continue
                    domains = r.json()

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

                        # Checkpoint
                        path = os.path.join(self._input_definition.metadata["checkpoint_dir"],domain)
                        try:
                            with open(path, "r") as f:
                                if latestbreach == f.read():
                                    #No new breaches for this domain
                                    continue
                        except:
                            pass

                        # Get all breached emails in domain
                        time.sleep(SLEEP)
                        url2 = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
                        with s.get(url2) as r:
                            if r.status_code == 404:
                                ew.log(EventWriter.INFO, f"{domain} has no breached accounts")
                                continue
                            if not r.ok:
                                ew.log(EventWriter.ERROR, f"{url2} returned {r.status_code}")
                                continue
                            emails = r.json()

                        collection = self.service.kvstore["hibp-pwned"]

                        for alias in emails:
                            breaches = emails[alias]
                            key = f"{alias}@{domain}"
                            #Pull this users record from KVstore
                            pwned = collection.data.query_by_id(id=key, fields="_key,Breaches")
                            ew.log(EventWriter.INFO, json.dumps(pwned))
                            if pwned:
                                newbreaches = [breach for breach in breaches if breach not in pwned[0]['Breaches']]
                            else:
                                newbreaches = breaches
                            #ew.log(EventWriter.INFO, json.dumps(newbreaches))
                            if newbreaches:
                                for breach in newbreaches:
                                    ew.write_event(
                                        Event(
                                            source=url2,
                                            sourcetype=f"hibp:pwned",
                                            data=f"{alias}@{domain} {breach}",
                                            unbroken=False,
                                        )
                                    )
                                if pwned:
                                    collection.data.update(pwned[0]['_key'],{"Breaches": breaches}) #"Alias": alias, "Domain": domain, 
                                else:
                                    collection.data.insert({"_key": f"{alias}@{domain}", "Breaches":  breaches})
                                

                        with open(path, "w") as f:
                            f.write(latestbreach)

if __name__ == "__main__":
    exitcode = Input().run(sys.argv)
    sys.exit(exitcode)
