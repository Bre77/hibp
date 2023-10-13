import os
import sys
import requests
import html
import re

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

    def update_breaches(self, ew, latestbreach):
        # Check if latest recorded breach has changed
        collection = self.service.kvstore["hibp-breaches"]

        lastbreach = collection.data.query(sort="AddedDate:", limit=1, fields="Name")[
            0
        ]["Name"]
        ew.log(
            EventWriter.INFO,
            f"TEST {latestbreach} {lastbreach}",
        )
        if latestbreach == lastbreach:
            ew.log(
                EventWriter.INFO,
                f"Already have latest breach {lastbreach}",
            )
            return

        # Get all breaches
        with requests.get("https://haveibeenpwned.com/api/v3/breaches") as r:
            if not r.ok:
                ew.log(
                    EventWriter.ERROR,
                    f"https://haveibeenpwned.com/api/v3/breaches returned {r.status_code}",
                )
                return
            breaches = r.json()

        # Update KVstore Collection
        NOTAG = re.compile("<.*?>")

        for breach in breaches:
            breach["Description"] = re.sub(
                NOTAG, "", html.unescape(breach["Description"])
            )
            key = breach["Name"]
            try:
                collection.data.update(key, breach)
            except:
                breach["_key"] = key
                collection.data.insert(breach)

    def update_pwned(self, ew, latestbreach):
        ew.log(EventWriter.DEBUG, "Getting API Keys")
        # Check API Key and domains
        apikeys = [
            x.clear_password
            for x in self.service.storage_passwords
            if x.realm == "hibp"
        ]

        if not apikeys:
            return

        collection = self.service.kvstore["hibp-pwned"]

        for apikey in apikeys:
            with requests.Session() as s:
                s.headers.update(
                    {"hibp-api-key": apikey, "user-agent": "HIBP-Splunk-App"}
                )

                # Get all domains
                url1 = "https://haveibeenpwned.com/api/v3/subscribeddomains"
                with s.get(url1) as r1:
                    if not r1.ok:
                        if r1.status_code == 401:
                            self.service.messages.create(
                                name="HIBP_APIKEY_401",
                                value="A Have I Been Pwned API key is no longer valid. [[/app/hibp/setup|Go to setup page]]",
                            )
                        ew.log(EventWriter.ERROR, f"{url1} returned {r1.status_code}")
                        continue
                    domains = r1.json()

                for d in domains:
                    ew.write_event(
                        Event(
                            source=url1,
                            sourcetype="hibp:domain",
                            data=f"{d['DomainName']} {d['NextSubscriptionRenewal']} {d['PwnCount']} {d['PwnCountExcludingSpamLists']} {d['PwnCountExcludingSpamListsAtLastSubscriptionRenewal']}",
                        )
                    )

                    domain = d["DomainName"]

                    # Get Domains Checkpoint
                    lastbreach = collection.data.query_by_id(domain)["Name"][0]
                    if latestbreach == lastbreach:
                        ew.log(
                            EventWriter.INFO,
                            f"Latest breach for {domain} hasnt changed from {lastbreach}, will not query HIBP",
                        )
                        continue

                    # Get all pwned emails in domain
                    url2 = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
                    with s.get(url2) as r2:
                        if r2.status_code == 404:
                            domainsearch = {}
                        elif not r2.ok:
                            ew.log(
                                EventWriter.ERROR, f"{url2} returned {r2.status_code}"
                            )
                            continue
                        else:
                            domainsearch = r2.json()

                    ew.log(
                        EventWriter.INFO,
                        f"{domain} has a total of {len(domainsearch)} pwned accounts",
                    )

                    for alias in domainsearch:
                        breaches = domainsearch[alias]
                        key = f"{alias}@{domain}"

                        # Pull this emails record from KVstore
                        try:
                            pwned = collection.data.query_by_id(key)
                        except:
                            pwned = None

                        # Find only new breaches by comparing API with KVstore
                        newbreaches = (
                            [
                                breach
                                for breach in breaches
                                if breach not in pwned["Breaches"]
                            ]
                            if pwned
                            else breaches
                        )

                        if newbreaches:
                            # Write event for each new breach
                            for breach in newbreaches:
                                ew.write_event(
                                    Event(
                                        source=url2,
                                        sourcetype=f"hibp:pwned",
                                        data=f"{alias}@{domain} {breach}",
                                    )
                                )
                            # Update or insert KVstore for this email
                            if pwned:
                                collection.data.update(key, {"Breaches": breaches})
                            else:
                                collection.data.insert(
                                    {"_key": key, "Breaches": breaches}
                                )

                    # Record checkpoint for this domain
                    if lastbreach:
                        collection.data.update(domain, {"Breaches": [latestbreach]})
                    else:
                        collection.data.insert(
                            {"_key": domain, "Breaches": [latestbreach]}
                        )

    def stream_events(self, inputs, ew):
        self.service.namespace["app"] = self.APP

        # Request latest breach
        with requests.get("https://haveibeenpwned.com/api/v3/latestbreach") as r:
            if not r.ok:
                ew.log(
                    EventWriter.ERROR,
                    f"https://haveibeenpwned.com/api/v3/latestbreach returned {r.status_code}",
                )
                return
            latestbreach = r.json()["Name"]

        # Update Breaches Lookup
        self.update_breaches(ew, latestbreach)

        # Update Pwned Events
        self.update_pwned(ew, latestbreach)

        ew.close()


if __name__ == "__main__":
    exitcode = Input().run(sys.argv)
    sys.exit(exitcode)
