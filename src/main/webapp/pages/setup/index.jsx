import Button from "@splunk/react-ui/Button";
import ControlGroup from "@splunk/react-ui/ControlGroup";
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
            fetch(`${splunkdPath}/servicesNS/nobody/hibp/storage/passwords`, {
                ...defaultFetchInit,
                method: "POST",
                params: { output_mode: "json" },
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

const Setup = () => {
    const queryClient = useQueryClient();

    const apikeys = useQuery({
        queryKey: ["apikeys"],
        queryFn: () =>
            fetch(`${splunkdPath}/servicesNS/nobody/hibp/storage/passwords`, {
                ...defaultFetchInit,
                params: { output_mode: "json", count: -1 },
            }).then((res) => (res.ok ? res.json() : Promise.reject())),
    });

    return (
        <>
            <AddEntry />
        </>
    );
};

Page(<Setup />);
