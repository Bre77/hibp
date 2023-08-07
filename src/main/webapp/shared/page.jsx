import layout from "@splunk/react-page";
import { getUserTheme } from "@splunk/splunk-utils/themes";
import { mixins, variables } from "@splunk/themes";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ReactQueryDevtools } from "@tanstack/react-query-devtools";
import React from "react";
import styled, { createGlobalStyle } from "styled-components";

const StyledContainer = styled.div`
    ${mixins.reset("inline")};
    display: block;
    font-size: ${variables.fontSizeLarge};
    line-height: 200%;
    margin: 0 ${variables.spacing} ${variables.spacing};
`;

// Theme based background colour
const GlobalStyle = createGlobalStyle`
    body {
        background-color: ${variables.backgroundColorPage};
    }
`;

// Setup the query client with defaults
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      cacheTime: Infinity,
      staleTime: Infinity,
      retry: (failureCount, error) => error >= 500 && failureCount < 3,
      refetchOnMount: false,
    },
  },
});

export const Page = (Child) =>
  Promise.all([getUserTheme()])
    .then(([theme]) =>
      layout(
        <QueryClientProvider client={queryClient}>
          <GlobalStyle />
          <StyledContainer>
            {Child}
          </StyledContainer>
          <ReactQueryDevtools />
        </QueryClientProvider>,
        { theme }
      )
    )
    .catch((e) => {
      const errorEl = document.createElement("span");
      errorEl.innerHTML = e;
      document.body.appendChild(errorEl);
    });
