# Have I Been Pwned Domain Search app for Splunk

Leverage the HIBP API v3 Domain Search to efficently monitor all your domains on Have I Been Pwned. This app will create an event each time an email address is found in a breach, and maintains an automatic lookup to enrich events with the full breach details, and includes useful dashboards. Supports multiple HIBP API keys, and monitoring multiple domains.

This app is unoffical and is not supported by Have I Been Pwned or Troy Hunt.

## Install
It is highly recommended you create a brand new index with very long retention for this data. The data volume is very small.

You must install and enable this app on your Search Head, or else the breaches lookup wont get populated.

You can optionally install and enable this on a Heavy Forwarder or Input Data Manager. Configure your HIBP API keys where ever you want the data to actually be collected.

This app requires the KV Store for both search time lookups and checkpoints.

## Troubleshooting

The modular input's logs can be found at `index=_internal component=ExecProcessor hibp_domainsearch`

This app requires the KV Store for both search time lookups and checkpoints.
