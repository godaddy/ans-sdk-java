package com.godaddy.ans.sdk.registration;

import com.godaddy.ans.sdk.config.AnsConfiguration;
import com.godaddy.ans.sdk.exception.AnsServerException;
import com.godaddy.ans.sdk.model.generated.AgentDetails;
import com.godaddy.ans.sdk.model.generated.AgentRegistrationRequest;
import com.godaddy.ans.sdk.model.generated.AgentRevocationRequest;
import com.godaddy.ans.sdk.model.generated.AgentRevocationResponse;
import com.godaddy.ans.sdk.model.generated.AgentStatus;
import com.godaddy.ans.sdk.model.generated.Link;
import com.godaddy.ans.sdk.model.generated.RegistrationPending;

import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Internal service for handling registration API calls.
 */
class RegistrationService {

    private final AnsApiClient httpClient;

    @Deprecated(since = "Use RegistrationService(AnsApiClient) constructor instead", forRemoval = true)
    RegistrationService(AnsConfiguration configuration) {
        this.httpClient = new AnsApiClient(configuration);
    }

    RegistrationService(final AnsApiClient ansApiClient) {
        this.httpClient = ansApiClient;
    }
    /**
     * Registers a new agent and returns full agent details.
     *
     * <p>This method registers the agent and then follows the 'self' link
     * to retrieve the complete AgentDetails including the agentId.</p>
     */
    AgentDetails register(AgentRegistrationRequest request) {
        String requestBody = httpClient.serializeToJson(request);

        HttpRequest httpRequest = httpClient.createRequestBuilder("/v1/agents/register")
            .POST(HttpRequest.BodyPublishers.ofString(requestBody))
            .build();

        HttpResponse<String> response = httpClient.sendRequest(httpRequest);
        RegistrationPending pending = httpClient.parseResponse(response.body(), RegistrationPending.class);

        // Follow the 'self' link to get full AgentDetails with agentId
        String selfPath = extractSelfLink(pending);
        if (selfPath == null) {
            throw new AnsServerException("Registration response missing 'self' link", 0, null);
        }

        return getAgentDetails(selfPath);
    }

    /**
     * Gets agent details by path.
     */
    AgentDetails getAgentDetails(String path) {
        HttpRequest httpRequest = httpClient.createRequestBuilder(path)
            .GET()
            .build();

        HttpResponse<String> response = httpClient.sendRequest(httpRequest);
        return httpClient.parseResponse(response.body(), AgentDetails.class);
    }

    /**
     * Gets agent details by agent ID.
     */
    AgentDetails getAgent(String agentId) {
        return getAgentDetails("/v1/agents/" + agentId);
    }

    /**
     * Triggers ACME verification.
     */
    AgentStatus verifyAcme(String agentId) {
        HttpRequest request = httpClient.createRequestBuilder("/v1/agents/" + agentId + "/verify-acme")
            .POST(HttpRequest.BodyPublishers.noBody())
            .build();

        HttpResponse<String> response = httpClient.sendRequest(request);
        return httpClient.parseResponse(response.body(), AgentStatus.class);
    }

    /**
     * Triggers DNS verification.
     */
    AgentStatus verifyDns(String agentId) {
        HttpRequest request = httpClient.createRequestBuilder("/v1/agents/" + agentId + "/verify-dns")
            .POST(HttpRequest.BodyPublishers.noBody())
            .build();

        HttpResponse<String> response = httpClient.sendRequest(request);
        return httpClient.parseResponse(response.body(), AgentStatus.class);
    }

    /**
     * Revokes an agent registration.
     *
     * <p>For ACTIVE agents, this revokes the agent's certificates and marks the
     * registration as REVOKED. For PENDING registrations (after ACME verification),
     * this cancels the registration and revokes any already-issued certificates.</p>
     *
     * @param agentId the agent ID to revoke
     * @param request the revocation request with reason and optional comments
     * @return the revocation response with details about DNS records to remove
     */
    AgentRevocationResponse revoke(String agentId, AgentRevocationRequest request) {
        String requestBody = httpClient.serializeToJson(request);

        HttpRequest httpRequest = httpClient.createRequestBuilder("/v1/agents/" + agentId + "/revoke")
            .POST(HttpRequest.BodyPublishers.ofString(requestBody))
            .build();

        HttpResponse<String> response = httpClient.sendRequest(httpRequest);
        return httpClient.parseResponse(response.body(), AgentRevocationResponse.class);
    }

    /**
     * Extracts the 'self' link path from a RegistrationPending response.
     */
    private String extractSelfLink(RegistrationPending pending) {
        if (pending.getLinks() == null) {
            return null;
        }
        for (Link link : pending.getLinks()) {
            if ("self".equals(link.getRel()) && link.getHref() != null) {
                return link.getHref().getPath();
            }
        }
        return null;
    }
}