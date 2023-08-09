import Button from "@splunk/react-ui/Button";
import Card from "@splunk/react-ui/Card";
import CardLayout from "@splunk/react-ui/CardLayout";
import ComboBox from "@splunk/react-ui/ComboBox";
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

const SubscriptionQuery = (apikey) => ({
    queryKey: ["subscription", apikey],
    queryFn: () =>
        fetch(`${splunkdPath}/services/hibp/api?output_mode=json`, {
            ...defaultFetchInit,
            method: "POST",
            body: makeBody({ apikey, endpoint: "subscription/status" }),
        }).then((res) => res.json().then((x) => (res.ok ? Promise.resolve(x) : Promise.reject(x.message)))),
});

const DomainQuery = (apikey) => ({
    queryKey: ["domains", apikey],
    queryFn: () =>
        fetch(`${splunkdPath}/services/hibp/api?output_mode=json`, {
            ...defaultFetchInit,
            method: "POST",
            body: makeBody({ apikey, endpoint: "subscribeddomains" }),
        }).then((res) => res.json().then((x) => (res.ok ? Promise.resolve(x) : Promise.reject(x.message)))),
});

const AddEntry = () => {
    const queryClient = useQueryClient();

    const [apiKey, setApiKey] = useState("");

    const addApiKey = useMutation({
        mutationFn: () =>
            queryClient.fetchQuery(SubscriptionQuery(apiKey)).then(() =>
                fetch(`${splunkdPath}/servicesNS/nobody/hibp/storage/passwords?output_mode=json`, {
                    ...defaultFetchInit,
                    method: "POST",
                    body: makeBody({ name: Date.now(), realm: "hibp", password: apiKey }),
                }).then((res) => (res.ok ? queryClient.invalidateQueries("apikeys") && setApiKey("") : Promise.reject()))
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
                res.ok ? res.json().then((x) => x.entry.map((y) => [y.name, y.content.clear_password])) : Promise.reject()
            ),
        placeholderData: [],
    });
    return (
        <CardLayout>
            {data.map(([name, apikey]) => (
                <ApiCard key={name} name={name} apikey={apikey} />
            ))}
        </CardLayout>
    );
};

const ApiCard = ({ name, apikey }) => {
    const queryClient = useQueryClient();
    const { data: subscription } = useQuery(SubscriptionQuery(apikey));
    const { data: domains } = useQuery(DomainQuery(apikey));

    const removeApiKey = useMutation({
        mutationFn: () =>
            fetch(`${splunkdPath}/servicesNS/nobody/hibp/storage/passwords/${name}?output_mode=json`, {
                ...defaultFetchInit,
                method: "DELETE",
            }).then((res) => (res.ok ? queryClient.invalidateQueries("apikeys") : Promise.reject())),
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
                <MutateButton mutation={removeApiKey} label="Remove" />
            </Card.Footer>
        </Card>
    );
};

const DISABLED = "Disabled";
const Input = () => {
    const [index, setIndex] = useState();
    const handleIndex = (e, { value }) => {
        setIndex(value);
        if (value === "Disabled") return;

    };
    const { data: input } = useQuery({
        queryKey: ["input"],
        queryFn: () => fetch(`${splunkdPath}/services/data/inputs/hibp?output_mode=json&search=datatype=event&search=isInternal=0`, defaultFetchInit).then((res) =>
        res.ok ? res.json().then((x) => x.entry.map((y) => y.name)) : Promise.reject()
    ),

    const { data: indexes } = useQuery({
        queryKey: ["indexes"],
        queryFn: () =>
            fetch(`${splunkdPath}/services/data/indexes?output_mode=json&search=datatype=event&search=isInternal=0`, defaultFetchInit).then((res) =>
                res.ok ? res.json().then((x) => x.entry.map((y) => y.name)) : Promise.reject()
            ),
        placeholderData: [],
    });
    console.log(indexes);
    return (
        <ControlGroup label="Input and Index">
            <ComboBox value={index} onChange={handleIndex}>
                <ComboBox.Option value="Disabled" />
                {indexes?.map((i) => (
                    <ComboBox.Option key={i} value={i} />
                ))}
            </ComboBox>
        </ControlGroup>
    );
};

const Setup = () => {
    return (
        <>
            <AddEntry />
            <Input />
            <Entries />
        </>
    );
};

Page(<Setup />);
