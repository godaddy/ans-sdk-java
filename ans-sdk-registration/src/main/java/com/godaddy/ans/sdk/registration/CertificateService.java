package com.godaddy.ans.sdk.registration;

import com.fasterxml.jackson.core.type.TypeReference;
import com.godaddy.ans.sdk.config.AnsConfiguration;
import com.godaddy.ans.sdk.exception.AnsAuthenticationException;
import com.godaddy.ans.sdk.exception.AnsNotFoundException;
import com.godaddy.ans.sdk.exception.AnsServerException;
import com.godaddy.ans.sdk.model.generated.CertificateResponse;

import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

/**
 * Service for retrieving agent certificates.
 *
 * <p>This service provides methods for retrieving issued identity and server
 * certificates for an agent.</p>
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * RegistrationClient client = RegistrationClient.builder()
 *     .environment(Environment.OTE)
 *     .credentialsProvider(new ApiKeyCredentialsProvider(apiKey, apiSecret))
 *     .build();
 *
 * // Get server certificates
 * List<CertificateResponse> serverCerts = client.certificates().getServerCertificates(agentId);
 *
 * // Get identity certificates
 * List<CertificateResponse> identityCerts = client.certificates().getIdentityCertificates(agentId);
 * }</pre>
 */
public class CertificateService {

    private final AnsApiClient httpClient;

    CertificateService(AnsConfiguration configuration) {
        this.httpClient = new AnsApiClient(configuration);
    }

    /**
     * Gets the identity certificates for an agent.
     *
     * <p>Identity certificates are used for agent-to-agent authentication
     * and contain the agent's ANS name in the Subject Alternative Name.</p>
     *
     * @param agentId the agent ID
     * @return list of identity certificates (may be empty if none issued yet)
     * @throws IllegalArgumentException if agentId is null or blank
     * @throws AnsNotFoundException if the agent is not found
     * @throws AnsAuthenticationException if authentication fails
     * @throws AnsServerException if there is a server error
     */
    public List<CertificateResponse> getIdentityCertificates(String agentId) {
        validateAgentId(agentId);

        HttpRequest request = httpClient.createRequestBuilder("/v1/agents/" + agentId + "/certificates/identity")
            .GET()
            .build();

        HttpResponse<String> response = httpClient.sendRequest(request);
        return httpClient.parseResponse(response.body(), new TypeReference<>() {});
    }

    /**
     * Gets the server certificates for an agent.
     *
     * <p>Server certificates are used for TLS connections to the agent's
     * endpoint and are bound via DANE/TLSA records in DNS.</p>
     *
     * @param agentId the agent ID
     * @return list of server certificates (may be empty if none issued yet)
     * @throws IllegalArgumentException if agentId is null or blank
     * @throws AnsNotFoundException if the agent is not found
     * @throws AnsAuthenticationException if authentication fails
     * @throws AnsServerException if there is a server error
     */
    public List<CertificateResponse> getServerCertificates(String agentId) {
        validateAgentId(agentId);

        HttpRequest request = httpClient.createRequestBuilder("/v1/agents/" + agentId + "/certificates/server")
            .GET()
            .build();

        HttpResponse<String> response = httpClient.sendRequest(request);
        return httpClient.parseResponse(response.body(), new TypeReference<>() {});
    }

    private void validateAgentId(String agentId) {
        if (agentId == null || agentId.isBlank()) {
            throw new IllegalArgumentException("agentId cannot be null or blank");
        }
    }
}