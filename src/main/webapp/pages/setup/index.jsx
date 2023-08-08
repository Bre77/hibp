import Button from "@splunk/react-ui/Button";
import Card from "@splunk/react-ui/Card";
import CardLayout from "@splunk/react-ui/CardLayout";
import ControlGroup from "@splunk/react-ui/ControlGroup";
import DL from "@splunk/react-ui/DefinitionList";
import Multiselect from "@splunk/react-ui/Multiselect";
import P from "@splunk/react-ui/Paragraph";
import Table from "@splunk/react-ui/Table";
import Text from "@splunk/react-ui/Text";
import { splunkdPath } from "@splunk/splunk-utils/config";
import { defaultFetchInit } from "@splunk/splunk-utils/fetch";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useState } from "react";

import Page from "../../shared/page";

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

const AddEntry = () => {
    const queryClient = useQueryClient();

    const [apiKey, setApiKey] = useState("");

    const addApiKey = useMutation({
        mutationFn: () =>
            fetch(`${splunkdPath}/services/hibp/api?output_mode=json`, {
                ...defaultFetchInit,
                method: "POST",
                body: makeBody({ apikey: apiKey, endpoint: "subscription/status" }),
            })
                .then((res) => res.json().then((data) => (res.ok ? Promise.resolve() : Promise.reject(data.message))))
                .then(() =>
                    fetch(`${splunkdPath}/servicesNS/nobody/hibp/storage/passwords?output_mode=json`, {
                        ...defaultFetchInit,
                        method: "POST",
                        body: makeBody({ name: Date.now(), realm: "hibp", password: apiKey }),
                    }).then((res) => (res.ok ? queryClient.invalidateQueries("apikeys") : Promise.reject()))
                ),
    });

    const handleApiKey = (e, { value }) => {
        setApiKey(value);
        addApiKey.reset();
    };

    return (
        <>
            <ControlGroup label="Add HIBP API Key" error={addApiKey.error}>
                <Text value={apiKey} onChange={handleApiKey} passwordVisibilityToggle error={apiKey.length > 0 && apiKey.length !== 32} />
                <MutateButton mutation={addApiKey} label="Add" disabled={apiKey.length !== 32} />
            </ControlGroup>
        </>
    );
};

const Entries = () => {
    const { data } = useQuery({
        queryKey: ["apikeys"],
        queryFn: () =>
            fetch(`${splunkdPath}/servicesNS/nobody/hibp/storage/passwords?output_mode=json&count=0&search=realm=hibp`, defaultFetchInit).then((res) =>
                res.ok ? res.json().then((x) => x.entry.map((y) => y.content.clear_password)) : Promise.reject()
            ),
        placeholderData: [],
    });
    return (
        <CardLayout>
            {data.map((apikey) => (
                <ApiCard apikey={apikey} />
            ))}
        </CardLayout>
    );
};

const ApiCard = ({ apikey }) => {
    console.log(apikey);
    const { data: subscription } = useQuery({
        queryKey: ["subscription", apikey],
        queryFn: () =>
            fetch(`${splunkdPath}/services/hibp/api?output_mode=json`, {
                ...defaultFetchInit,
                method: "POST",
                body: makeBody({ apikey, endpoint: "subscription/status" }),
            }).then((res) => res.json().then((x) => (res.ok ? Promise.resolve(x) : Promise.reject(x.message)))),
    });
    const { data: domains } = useQuery({
        queryKey: ["domains", apikey],
        queryFn: () =>
            fetch(`${splunkdPath}/services/hibp/api?output_mode=json`, {
                ...defaultFetchInit,
                method: "POST",
                body: makeBody({ apikey, endpoint: "subscribeddomains" }),
            }).then((res) => res.json().then((x) => (res.ok ? Promise.resolve(x) : Promise.reject(x.message)))),
    });

    return (
        <Card style={{ maxWidth: "40em" }}>
            <Card.Header title={`${subscription?.SubscriptionName || "Loading"} subscription`} />
            <Card.Body>
                <P>{subscription?.Description}</P>
                <Table>
                    <Table.Head>
                        <Table.HeadCell>Domain</Table.HeadCell>
                        <Table.HeadCell>Pwned</Table.HeadCell>
                        <Table.HeadCell>Change</Table.HeadCell>
                    </Table.Head>
                    <Table.Body>
                        {domains?.map((domain) => (
                            <Table.Row key={domain.DomainName}>
                                <Table.Cell>{domain.DomainName}</Table.Cell>
                                <Table.Cell>{domain.PwnCount}</Table.Cell>
                                <Table.Cell>{domain.PwnCount - (domain.PwnCountExcludingSpamListsAtLastSubscriptionRenewal || 0)}</Table.Cell>
                            </Table.Row>
                        ))}
                    </Table.Body>
                </Table>
            </Card.Body>
            <Card.Footer showBorder={false}>
                <Button label="Remove" />
            </Card.Footer>
        </Card>
    );
};

const Setup = () => {
    return (
        <>
            <AddEntry />
            <Entries />
        </>
    );
};

Page(<Setup />);
