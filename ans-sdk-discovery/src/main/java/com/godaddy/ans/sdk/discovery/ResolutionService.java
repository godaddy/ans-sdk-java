package com.godaddy.ans.sdk.discovery;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.godaddy.ans.sdk.auth.AnsCredentials;
import com.godaddy.ans.sdk.config.AnsConfiguration;
import com.godaddy.ans.sdk.exception.AnsAuthenticationException;
import com.godaddy.ans.sdk.exception.AnsNotFoundException;
import com.godaddy.ans.sdk.exception.AnsServerException;
import com.godaddy.ans.sdk.exception.AnsValidationException;
import com.godaddy.ans.sdk.http.HttpClientFactory;
import com.godaddy.ans.sdk.model.generated.AgentCapabilityRequest;
import com.godaddy.ans.sdk.model.generated.AgentDetails;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Internal service for handling agent resolution API calls.
 */
class ResolutionService {

    private final AnsConfiguration configuration;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    ResolutionService(AnsConfiguration configuration) {
        this.configuration = configuration;
        this.httpClient = HttpClientFactory.create(configuration);
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        this.objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    /**
     * Resolves an agent by agentHost and optional version constraint.
     *
     * @param agentHost the agent's host
     * @param version optional version constraint (e.g., "^1.0.0", "~1.2.0", "1.2.3")
     * @return the resolved agent details
     * @throws AnsNotFoundException if no matching agent is found
     * @throws AnsAuthenticationException if authentication fails
     */
    AgentDetails resolve(String agentHost, String version) {
        // Step 1: POST to /v1/agents/resolution to get the agent-details link
        String resolveVersion = (version != null && !version.isEmpty()) ? version : "*";
        AgentCapabilityRequest request = new AgentCapabilityRequest()
            .agentHost(agentHost)
            .version(resolveVersion);
        String requestBody = serializeToJson(request);

        HttpRequest resolutionRequest = createRequestBuilder("/v1/agents/resolution")
            .POST(HttpRequest.BodyPublishers.ofString(requestBody))
            .build();

        HttpResponse<String> resolutionResponse = sendRequest(resolutionRequest);

        // Step 2: Parse the resolution response to find the agent-details link
        String agentDetailsUrl = extractAgentDetailsLink(resolutionResponse.body());

        // Step 3: GET the full agent details from the link
        HttpRequest detailsRequest = createRequestBuilder(agentDetailsUrl)
            .GET()
            .build();

        HttpResponse<String> detailsResponse = sendRequest(detailsRequest);

        // Step 4: Parse and return the AgentDetails using Jackson
        return parseAgentDetails(detailsResponse.body());
    }

    /**
     * Serializes an object to JSON using ObjectMapper.
     */
    private String serializeToJson(Object object) {
        try {
            return objectMapper.writeValueAsString(object);
        } catch (IOException e) {
            throw new AnsServerException("Failed to serialize request: " + e.getMessage(), 0, e, null);
        }
    }

    /**
     * Extracts the agent-details link from the resolution response.
     */
    private String extractAgentDetailsLink(String responseBody) {
        try {
            var responseNode = objectMapper.readTree(responseBody);
            var linksNode = responseNode.get("links");
            if (linksNode != null && linksNode.isArray()) {
                for (var linkNode : linksNode) {
                    String rel = linkNode.has("rel") ? linkNode.get("rel").asText() : null;
                    if ("agent-details".equals(rel)) {
                        String href = linkNode.get("href").asText();
                        // If href is absolute URL, extract the path
                        String path;
                        if (href.startsWith("http")) {
                            URI uri = URI.create(href);
                            path = uri.getPath();
                        } else {
                            path = href;
                        }
                        // Validate the path to prevent SSRF-adjacent attacks
                        validateAgentDetailsPath(path);
                        return path;
                    }
                }
            }
            throw new AnsServerException("Resolution response missing agent-details link", 0, null);
        } catch (IOException e) {
            throw new AnsServerException("Failed to parse resolution response: " + e.getMessage(), 0, e, null);
        }
    }

    /**
     * Validates that the agent-details path matches expected pattern.
     * Prevents SSRF-adjacent attacks where a compromised response could
     * redirect the SDK to unintended endpoints.
     */
    private void validateAgentDetailsPath(String path) {
        // Path must start with /v1/agents/
        if (!path.startsWith("/v1/agents/")) {
            throw new AnsServerException(
                "Invalid agent-details link: path must start with /v1/agents/, got: " + path, 0, null);
        }
        // Path must not contain path traversal sequences
        if (path.contains("..")) {
            throw new AnsServerException(
                "Invalid agent-details link: path contains illegal traversal sequence: " + path, 0, null);
        }
    }

    /**
     * Parses the agent details response into an AgentDetails object using Jackson.
     */
    private AgentDetails parseAgentDetails(String responseBody) {
        try {
            return objectMapper.readValue(responseBody, AgentDetails.class);
        } catch (IOException e) {
            throw new AnsServerException("Failed to parse agent details: " + e.getMessage(), 0, e, null);
        }
    }

    /**
     * Gets agent details by agent ID.
     *
     * @param agentId the agent ID
     * @return the agent details
     * @throws AnsNotFoundException if the agent is not found
     * @throws AnsAuthenticationException if authentication fails
     */
    AgentDetails getAgent(String agentId) {
        HttpRequest request = createRequestBuilder("/v1/agents/" + agentId)
            .GET()
            .build();

        HttpResponse<String> response = sendRequest(request);
        return parseAgentDetails(response.body());
    }

    /**
     * Sends an HTTP request and handles common error responses.
     */
    private HttpResponse<String> sendRequest(HttpRequest request) {
        try {
            HttpResponse<String> response = httpClient.send(
                request, HttpResponse.BodyHandlers.ofString());
            handleErrorResponse(response);
            return response;
        } catch (IOException e) {
            throw new AnsServerException("Network error: " + e.getMessage(), 0, e, null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AnsServerException("Request interrupted", 0, e, null);
        }
    }

    /**
     * Handles error responses from the API.
     */
    private void handleErrorResponse(HttpResponse<String> response) {
        int statusCode = response.statusCode();

        if (statusCode >= 200 && statusCode < 300) {
            return; // Success
        }

        String requestId = response.headers().firstValue("X-Request-Id").orElse(null);
        String body = response.body();

        switch (statusCode) {
            case 401, 403 -> throw new AnsAuthenticationException(
                "Authentication failed: " + body, null, requestId);
            case 404 -> throw new AnsNotFoundException(
                "Agent not found: " + body, null, null, requestId);
            case 422 -> throw new AnsValidationException(
                "Validation error: " + body, null, requestId);
            default -> {
                if (statusCode >= 500) {
                    throw new AnsServerException(
                        "Server error: " + body, statusCode, requestId);
                }
                throw new AnsServerException(
                    "Unexpected error (" + statusCode + "): " + body, statusCode, requestId);
            }
        }
    }

    /**
     * Creates a request builder with common headers.
     */
    private HttpRequest.Builder createRequestBuilder(String path) {
        AnsCredentials credentials = configuration.getCredentialsProvider().resolveCredentials();

        URI uri;
        try {
            uri = URI.create(configuration.getBaseUrl() + path);
        } catch (IllegalArgumentException e) {
            throw new AnsServerException(
                "Invalid URL: " + configuration.getBaseUrl() + path + " - " + e.getMessage(), 0, e, null);
        }

        return HttpRequest.newBuilder()
            .uri(uri)
            .header("Authorization", credentials.toAuthorizationHeader())
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .timeout(configuration.getReadTimeout());
    }
}