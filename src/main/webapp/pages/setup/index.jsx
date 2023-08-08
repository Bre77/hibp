import Button from "@splunk/react-ui/Button";
import ControlGroup from "@splunk/react-ui/ControlGroup";
import Multiselect from "@splunk/react-ui/Multiselect";
import Table from "@splunk/react-ui/Table";
import Text from "@splunk/react-ui/Text";
import { splunkdPath } from "@splunk/splunk-utils/config";
import { defaultFetchInit } from "@splunk/splunk-utils/fetch";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import React, { useState } from "react";

import Page from "../../shared/page";

const QUERY_API = {
    queryKey: ["domains"],
    queryFn: () =>
        fetch(`${splunkdPath}/servicesNS/nobody/hibp/storage/passwords?output_mode=json&count=0&search=realm=hibp`, defaultFetchInit).then((res) =>
            res.ok ? res.json().then((x) => x.entry.map((y) => y.content)) : Promise.reject()
        ),
    placeholderData: [],
};

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
    const handleApiKey = (e, { value }) => setApiKey(value);
    const [domains, setDomains] = useState([]);
    const handleDomains = (e, { values }) => setDomains(values);

    const entries = useQuery(QUERY_API).data || [];

    const subscribeddomains = useQuery({
        queryKey: ["apikeys", apiKey],
        queryFn: () =>
            fetch(`${splunkdPath}/services/hibp/api?output_mode=json`, {
                ...defaultFetchInit,
                method: "POST",
                body: makeBody({ apikey: apiKey, endpoint: "subscribeddomains" }),
                placeholderData: [],
            })
                .then((res) => (res.ok ? res.json() : Promise.reject()))
                .then((x) => {
                    const active = entries.map((x) => x.username);
                    const d = x.map((y) => y.DomainName).filter((z) => !active.includes(z));
                    console.log(active, x, d);
                    setDomains(d);
                    return d;
                }),
        enabled: apiKey.length === 32,
    });

    const addApiKey = useMutation({
        mutationFn: () =>
            Promise.all(
                domains.map((domain) =>
                    fetch(`${splunkdPath}/servicesNS/nobody/hibp/storage/passwords?output_mode=json`, {
                        ...defaultFetchInit,
                        method: "POST",
                        body: makeBody({ name: domain, realm: "hibp", password: apiKey }),
                    }).then((res) => (res.ok ? queryClient.invalidateQueries("domains") && setDomains([]) : Promise.reject()))
                )
            ),
    });

    return (
        <>
            <ControlGroup label="API Key" error={subscribeddomains.error}>
                <Text value={apiKey} onChange={handleApiKey} passwordVisibilityToggle error={apiKey.length > 0 && apiKey.length !== 32} />
            </ControlGroup>
            <ControlGroup label="Domains">
                <Multiselect values={domains} onChange={handleDomains} isLoadingOptions={subscribeddomains.isLoading} disabled={!subscribeddomains.data}>
                    {subscribeddomains.data && subscribeddomains.data.map((x) => <Multiselect.Option key={x} label={x} value={x} />)}
                </Multiselect>
            </ControlGroup>
            <ControlGroup label="">
                <MutateButton mutation={addApiKey} label="Add" disabled={domains.length === 0} />
            </ControlGroup>
        </>
    );
};

const Entries = () => {
    const { data } = useQuery(QUERY_API);
    return (
        <Table stripeRows>
            <Table.Head>
                <Table.HeadCell>Domain</Table.HeadCell>
                <Table.HeadCell>API Key</Table.HeadCell>
                <Table.HeadCell>Delete</Table.HeadCell>
            </Table.Head>
            <Table.Body>
                {data.map((x) => (
                    <Table.Row key={x.username}>
                        <Table.Cell>{x.username}</Table.Cell>
                        <Table.Cell>{x.clear_password.slice(0, 5)}...</Table.Cell>
                        <Table.Cell></Table.Cell>
                    </Table.Row>
                ))}
            </Table.Body>
        </Table>
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
