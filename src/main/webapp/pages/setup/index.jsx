import Button from "@splunk/react-ui/Button";
import Card from "@splunk/react-ui/Card";
import CardLayout from "@splunk/react-ui/CardLayout";
import ControlGroup from "@splunk/react-ui/ControlGroup";
import Link from "@splunk/react-ui/Link";
import P from "@splunk/react-ui/Paragraph";
import Table from "@splunk/react-ui/Table";
import Text from "@splunk/react-ui/Text";
import { splunkdPath } from "@splunk/splunk-utils/config";
import { defaultFetchInit } from "@splunk/splunk-utils/fetch";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useState } from "react";
import Page from "../../shared/page";

const WIDTH = 80;

const makeBody = (data) => {
    return Object.entries(data).reduce((form, [key, value]) => {
        form.append(key, value);
        return form;
    }, new URLSearchParams());
};

const MutateButton = ({ mutation, label, disabled = false }) => (
    <Button
        appearance={{ idle: "default", loading: "pill", success: "primary", error: "destructive" }[mutation.status]}
        onClick={mutation.mutate}
        disabled={mutation.isLoading || disabled}
        label={{ idle: label, loading: "Running", success: "Success", error: "Failed" }[mutation.status]}
    />
);

const HandleHIBP = (res) => (res.ok ? res.json().then((data) => Promise.resolve(data)) : Promise.reject(res.status));

const SubscriptionQuery = (apikey) => ({
    queryKey: ["subscription", apikey],
    queryFn: () =>
        fetch(`${splunkdPath}/services/hibp/api?output_mode=json`, {
            ...defaultFetchInit,
            method: "POST",
            body: makeBody({ apikey, endpoint: "subscription/status" }),
        }).then(HandleHIBP),
});

const DomainQuery = (apikey) => ({
    queryKey: ["domains", apikey],
    queryFn: () =>
        fetch(`${splunkdPath}/services/hibp/api?output_mode=json`, {
            ...defaultFetchInit,
            method: "POST",
            body: makeBody({ apikey, endpoint: "subscribeddomains" }),
        }).then(HandleHIBP),
});

const ERRORS = {
    400: "Bad request: contact splunkbase@ba.id.au",
    401: "Unauthorised: API key is not valid",
    429: "Too many requests: try again in 10 minutes",
    503: "Service unavailable: try again later",
};

const AddEntry = () => {
    const queryClient = useQueryClient();

    const [apiKey, setApiKey] = useState("");

    const addApiKey = useMutation({
        mutationFn: () =>
            queryClient.fetchQuery(SubscriptionQuery(apiKey)).then(
                () =>
                    fetch(`${splunkdPath}/servicesNS/nobody/hibp/storage/passwords?output_mode=json`, {
                        ...defaultFetchInit,
                        method: "POST",
                        body: makeBody({ name: Date.now(), realm: "hibp", password: apiKey }),
                    }).then((res) => (res.ok ? queryClient.invalidateQueries("apikeys") && setApiKey("") : Promise.reject(res.statusText))),
                (status) => Promise.reject(ERRORS?.[status] || `API returned with status ${status}`)
            ),
    });

    const handleApiKey = (e, { value }) => {
        setApiKey(value);
        addApiKey.reset();
    };

    return (
        <>
            <ControlGroup
                labelWidth={WIDTH}
                label="Add API Key"
                error={addApiKey.error}
                help={
                    <>
                        Get from{" "}
                        <Link to="https://haveibeenpwned.com/API/Key?ref=HIBP-Splunk-App" openInNewContext>
                            haveibeenpwned.com/API/Key
                        </Link>
                    </>
                }
            >
                <Text value={apiKey} onChange={handleApiKey} passwordVisibilityToggle error={apiKey.length > 0 && apiKey.length !== 32} />
                <MutateButton mutation={addApiKey} label="Add" disabled={apiKey.length !== 32} />
            </ControlGroup>
        </>
    );
};

const ApiCard = ({ name, apikey }) => {
    const queryClient = useQueryClient();
    const subscription = useQuery(SubscriptionQuery(apikey));
    const domains = useQuery(DomainQuery(apikey));

    const removeApiKey = useMutation({
        mutationFn: () =>
            fetch(`${splunkdPath}/servicesNS/nobody/hibp/storage/passwords/${name}?output_mode=json`, {
                ...defaultFetchInit,
                method: "DELETE",
            }).then((res) => (res.ok ? queryClient.invalidateQueries("apikeys") : Promise.reject(res.statusCode))),
    });

    if ((subscription.isError && subscription.error === 401) || (domains.isError && domains.error === 401)) {
        return (
            <>
                <Card.Header title="API Key Invalid" />
                <Card.Body>
                    <P>
                        This API Key has returned status 401, so it is invalid and should be removed.
                        <br />
                        Visit{" "}
                        <Link to="https://haveibeenpwned.com/API/Key?ref=HIBP-Splunk-App" openInNewContext>
                            haveibeenpwned.com/API/Key
                        </Link>{" "}
                        to generate a new API key.
                    </P>
                </Card.Body>
                <Card.Footer showBorder={false}>
                    <MutateButton mutation={removeApiKey} label="Remove" />
                </Card.Footer>
            </>
        );
    }

    if ((subscription.isError && subscription.error === 429) || (domains.isError && domains.error === 429)) {
        return (
            <>
                <Card.Header title="API Key Rate Limit Exceeded" />
                <Card.Body>
                    <P>
                        This page retrieves the latest data from Have I Been Pwned, however there is a rate limit to prevent these endpoints being used too
                        frequently. Try again in 10 minutes.
                    </P>
                </Card.Body>
                <Card.Footer showBorder={false}>
                    <MutateButton mutation={removeApiKey} label="Remove" />
                </Card.Footer>
            </>
        );
    }

    return (
        <>
            <Card.Header title={`${subscription.data?.SubscriptionName || "Loading"} subscription`} />
            <Card.Body>
                <P>{subscription.data?.Description}</P>
                <Table stripeRows>
                    <Table.Head>
                        <Table.HeadCell>Domain</Table.HeadCell>
                        <Table.HeadCell>Pwned</Table.HeadCell>
                        <Table.HeadCell>Change</Table.HeadCell>
                    </Table.Head>
                    <Table.Body>
                        {domains.data?.map((domain) => (
                            <Table.Row key={domain.DomainName}>
                                <Table.Cell>{domain.DomainName}</Table.Cell>
                                <Table.Cell>{domain.PwnCountExcludingSpamLists}</Table.Cell>
                                <Table.Cell>{domain.PwnCountExcludingSpamLists - (domain.PwnCountExcludingSpamListsAtLastSubscriptionRenewal || 0)}</Table.Cell>
                            </Table.Row>
                        ))}
                    </Table.Body>
                </Table>
            </Card.Body>
            <Card.Footer showBorder={false}>
                <MutateButton mutation={removeApiKey} label="Remove" />
            </Card.Footer>
        </>
    );
};

const DISABLED = "";

const INPUT_LABELS = [
    ["Update Index", "Save and Enable"],
    ["Disable Input", "Already Disabled"],
];
const Input = () => {
    const queryClient = useQueryClient();
    const [local, setLocal] = useState(DISABLED);

    const updateRemote = useMutation({
        mutationFn: () =>
            fetch(`${splunkdPath}/services/hibp/input?output_mode=json`, {
                ...defaultFetchInit,
                method: "POST",
                body: makeBody({ index: local }),
            }).then((res) => (res.ok ? queryClient.invalidateQueries({ queryKey: ["input"] }) : res.text().then((error) => Promise.reject(error)))),
    });

    const handleLocal = (e, { value }) => {
        updateRemote.reset();
        setLocal(value);
    };

    const { data: remote } = useQuery({
        queryKey: ["input"],
        queryFn: () =>
            fetch(`${splunkdPath}/servicesNS/nobody/hibp/configs/conf-inputs/hibp_domainsearch%3A%252F%252Fdefault?output_mode=json`, defaultFetchInit).then(
                (res) =>
                    res.ok ? res.json().then(({ entry }) => (entry[0].content.disabled ? DISABLED : entry[0].content.index)) : Promise.reject(res.statusCode)
            ),
        placeholderData: DISABLED,
        onSuccess: (data) => setLocal(data),
    });
    console.log(local, remote, +(local === DISABLED), +(remote === DISABLED));

    return (
        <ControlGroup labelWidth={WIDTH} label="Splunk Index" help="Create an event index with long retention, then set it here to enable.">
            <Text value={local} onChange={handleLocal} placeholder="Disabled" />
            <MutateButton mutation={updateRemote} label={INPUT_LABELS[+(local === DISABLED)][+(remote === DISABLED)]} disabled={local === remote} />
        </ControlGroup>
    );
};

const Help = () => {
    return (
        <ControlGroup
            labelWidth={WIDTH}
            label="Support"
            help={
                <>
                    This app was created by{" "}
                    <Link to="https://bre77.au?ref=HIBP-Splunk-App" openInNewContext>
                        Brett Adams
                    </Link>
                    .
                </>
            }
        >
            <Button to="/app/hibp/search?q=search%20index%3D_internal%20component%3DExecProcessor%20hibp_domainsearch.py">Internal Logs</Button>
            <Button to="https://github.com/Bre77/hibp/issues" openInNewContext>
                Issues
            </Button>
            <Button to="slack://user?team=T047WPASC&id=U6MV3Q9UH" openInNewContext>
                Slack
            </Button>
            <Button to="mailto:splunkbase@ba.id.au" openInNewContext>
                Email
            </Button>
        </ControlGroup>
    );
};

const Setup = () => {
    const { data } = useQuery({
        queryKey: ["apikeys"],
        queryFn: () =>
            fetch(`${splunkdPath}/servicesNS/nobody/hibp/storage/passwords?output_mode=json&count=0&search=realm=hibp`, defaultFetchInit).then((res) =>
                res.ok
                    ? res.json().then(({ entry }) => entry.map((password) => [password.name, password.content.clear_password]))
                    : Promise.reject(res.statusCode)
            ),
        placeholderData: [],
    });
    return (
        <CardLayout cardWidth={570} gutterSize={13}>
            <Card>
                <Card.Header title="Setup Have I Been Pwned Domain Search" />
                <Card.Body>
                    <AddEntry />
                    <Input />
                    <Help />
                </Card.Body>
            </Card>
            {data.map(([name, apikey]) => (
                <Card key={name}>
                    <ApiCard key={name} name={name} apikey={apikey} />
                </Card>
            ))}
        </CardLayout>
    );
};

Page(<Setup />);
