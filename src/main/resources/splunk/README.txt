# Have I Been Pwned Domain Search app for Splunk

Leverage the Have I Been Pwned Domain Search API to efficiently monitor for breaches on all your domains directly in Splunk. This app supports multiple API Keys and works on all Splunk deployment types, including Splunk Cloud.

https://splunkbase.splunk.com/app/6996
https://github.com/Bre77/hibp

## Description

This app will create an event each time an email address is found in a breach on Have I Been Pwned, and maintains an automatic lookup to enrich these events with the full breach details without wasting ingest license usage. The app also includes multiple dashboards to help you understand the data out of the box. Supports multiple HIBP API keys, and monitoring multiple domains.

Works on all Splunk deployment types, including Splunk Cloud. See installation instructions for more details.

This app was created by Brett Adams, and is not supported by Have I Been Pwned or Troy Hunt.

## Install

It is strongly recommended you create a new index with very long retention for this data. The data generated by this app is very small in size.

You **must** install and enable this app on your Search Head, or else the breaches lookup wont get populated.

You can _optionally_ install and enable this on a Heavy Forwarder or Input Data Manager. Configure your HIBP API keys where you want the data to actually be collected.

This app requires the KV Store for both search time lookups and input time checkpoints.

## Troubleshooting

The modular input's logs can be found at `index=_internal component=ExecProcessor hibp_domainsearch`

This app requires the KV Store for both search time lookups and checkpoints.

## Credits

This app was created and is supported by Brett Adams (@Bre77).

Special Thanks to James Hodgkinson (@yaleman) for providing access to his domain for development and testing.

Special Thanks to Troy Hunt (@troyhunt) for creating Have I Been Pwned, the Domain Search API, and collaborating with me on the new API endpoints and rating limiting. You can read more about this at https://www.troyhunt.com/all-new-have-i-been-pwned-domain-search-apis-and-splunk-integration?ref=HIBP-Splunk-App
