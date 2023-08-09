import os
import sys
import csv
import json
import requests
from splunk.rest import simpleRequest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.modularinput import Script, Scheme, Argument, Event, EventWriter

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
        path = os.path.join(self._input_definition.metadata["checkpoint_dir"],"lastestbreach"
        with open(path), "r") as f:
            if latestbreach == f.read():
                ew.log(EventWriter.INFO, f"Latest breach hasnt changed from {latestbreach}, will not update breaches lookup")
                return
        
        # Get all breaches
        with requests.get("https://haveibeenpwned.com/api/v3/breaches") as r:
            if not r.ok:
                ew.log(EventWriter.ERROR, f"https://haveibeenpwned.com/api/v3/breaches returned {r.status_code}")
                return
            breaches = r.json()

        #Update CSV Lookup
        try:
            with open(os.path.join(os.getenv('SPLUNK_HOME'),"etc","apps",self.APP,"lookups","hibp-breaches.csv"), "w") as f:
                with csv.writer(f) as writer:
                    csv_writer.writerow(["Name","Title","Domain","BreachDate","AddedDate","ModifiedDate","PwnCount","Description","LogoPath","DataClasses","IsVerified","IsFabricated","IsSensitive","IsRetired","IsSpamList","IsMalware"])
                    for breach in breaches:
                        writer.writerow([breach["Name"],breach["Title"],breach["Domain"],breach["BreachDate"],breach["AddedDate"],breach["ModifiedDate"],breach["PwnCount"],breach["Description"],breach["LogoPath"],",".join(breach["DataClasses"]),breach["IsVerified"],breach["IsFabricated"],breach["IsSensitive"],breach["IsRetired"],breach["IsSpamList"],breach["IsMalware"]])
        except:
            ew.log(EventWriter.ERROR, f"Failed to update hibp-breaches.csv lookup")
            return

        with open(path, "r") as f:
            f.write(latestbreach)

    def stream_events(self, inputs, ew):
        self.service.namespace["app"] = self.APP
        # Get Variables
        input_name, input_items = inputs.inputs.popitem()
        kind, name = input_name.split("://")

        # Request latest breach
        with requests.get("https://haveibeenpwned.com/api/v3/latestbreach") as r:
            if not r.ok:
                ew.log(EventWriter.ERROR, f"https://haveibeenpwned.com/api/v3/latestbreach returned {r.status_code}")
                return
            latestbreach = r.json()['Name']

        # Update CSV Lookup
        self.update_lookup(ew, latestbreach)
        
        # Check API Key and domains
        apikeys = [
            x
            for x in self.service.storage_passwords
            if x.realm == "hibp"
        ]

        for apikey in apikeys:
            with requests.Session() as s:
                s.headers.update({"hibp-api-key": apikey, "user-agent": "HIBP-Splunk-App"})

                # Get all domains
                with s.get("https://haveibeenpwned.com/api/v3/subscribeddomains") as r:
                    if not r.ok:
                        ew.log(EventWriter.ERROR, f"https://haveibeenpwned.com/api/v3/subscribeddomains returned {r.status_code}")
                        continue
                    domains = r.json()

                    for d in domains:
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
                        with s.get(f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}") as r:
                            if not r.ok:
                                ew.log(EventWriter.ERROR, f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain} returned {r.status_code}")
                                continue
                            emails = r.json()

                            for alias in emails:
                                for breach in emails[alias]
                                    ew.write_event(
                                        Event(
                                            sourcetype=f"hibp:pwned",
                                            data=f"{alias} {breach}",
                                        )
                                    )

                        with open(path, "w") as f:
                            f.write(latestbreach)

if __name__ == "__main__":
    exitcode = Input().run(sys.argv)
    sys.exit(exitcode)
