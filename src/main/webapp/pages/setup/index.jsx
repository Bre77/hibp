import Button from "@splunk/react-ui/Button";
import ControlGroup from "@splunk/react-ui/ControlGroup";
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
    const [domain, setDomain] = useState("");
    const handleDomain = (e, { value }) => setDomain(value);
    const [apiKey, setApiKey] = useState("");
    const handleApiKey = (e, { value }) => setApiKey(value);

    const addApiKey = useMutation({
        mutationFn: () =>
            fetch(`${splunkdPath}/servicesNS/nobody/hibp/storage/passwords?output_mode=json`, {
                ...defaultFetchInit,
                method: "POST",
                body: makeBody({ name: domain, realm: "hibp", password: apiKey }),
            }).then((res) => (res.ok ? queryClient.invalidateQueries("apikeys") && setDomain("") && setApiKey("") : Promise.reject())),
    });
    return (
        <>
            <ControlGroup label="Domain">
                <Text value={domain} onChange={handleDomain} />
            </ControlGroup>
            <ControlGroup label="API Key">
                <Text value={apiKey} onChange={handleApiKey} passwordVisibilityToggle />
            </ControlGroup>
            <ControlGroup label="">
                <MutateButton mutation={addApiKey} label="Add" />
            </ControlGroup>
            <span>
                {domain} {apiKey}
            </span>
        </>
    );
};

const Entries = () => {
    const { data } = useQuery({
        queryKey: ["apikeys"],
        queryFn: () =>
            fetch(`${splunkdPath}/servicesNS/nobody/hibp/storage/passwords?output_mode=json&count=0&search=realm=hibp`, defaultFetchInit).then((res) =>
                res.ok ? res.json().then((x) => x.entry.map((y) => y.content)) : Promise.reject()
            ),
        placeholderData: [],
    });
    return (
        <Table stripeRows>
            <Table.Head>
                <Table.HeadCell>Domain</Table.HeadCell>
                <Table.HeadCell>API Key</Table.HeadCell>
                <Table.HeadCell>Delete</Table.HeadCell>
            </Table.Head>
            <Table.Body>
                {data.map((x) => (
                    <Table.Row>
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
