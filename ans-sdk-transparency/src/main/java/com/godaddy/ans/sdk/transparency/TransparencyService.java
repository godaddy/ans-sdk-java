package com.godaddy.ans.sdk.transparency;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.godaddy.ans.sdk.exception.AnsNotFoundException;
import com.godaddy.ans.sdk.exception.AnsServerException;
import com.godaddy.ans.sdk.transparency.model.AgentAuditParams;
import com.godaddy.ans.sdk.transparency.model.CheckpointHistoryParams;
import com.godaddy.ans.sdk.transparency.model.CheckpointHistoryResponse;
import com.godaddy.ans.sdk.transparency.model.CheckpointResponse;
import com.godaddy.ans.sdk.transparency.model.TransparencyLog;
import com.godaddy.ans.sdk.transparency.model.TransparencyLogAudit;
import com.godaddy.ans.sdk.transparency.model.TransparencyLogV0;
import com.godaddy.ans.sdk.transparency.model.TransparencyLogV1;
import com.godaddy.ans.sdk.transparency.scitt.RefreshDecision;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.StringJoiner;
import java.util.concurrent.CompletableFuture;

/**
 * Internal service for handling transparency log API calls.
 */
class TransparencyService implements AutoCloseable {

    private static final Logger LOGGER = LoggerFactory.getLogger(TransparencyService.class);
    private static final String SCHEMA_VERSION_HEADER = "X-Schema-Version";

    private final String baseUrl;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Duration readTimeout;
    private final RootKeyManager rootKeyManager;

    TransparencyService(String baseUrl, Duration connectTimeout, Duration readTimeout, Duration rootKeyCacheTtl) {
        this.baseUrl = baseUrl;
        this.readTimeout = readTimeout;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(connectTimeout)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        this.objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        this.rootKeyManager = new RootKeyManager(httpClient, baseUrl, readTimeout, rootKeyCacheTtl);
    }

    /**
     * Gets the transparency log entry for an agent.
     */
    TransparencyLog getAgentTransparencyLog(String agentId) {
        String path = "/v1/agents/" + URLEncoder.encode(agentId, StandardCharsets.UTF_8);
        return fetchWithSchemaVersion(path);
    }

    /**
     * Gets the audit trail for an agent.
     */
    TransparencyLogAudit getAgentTransparencyLogAudit(String agentId, AgentAuditParams params) {
        String path = "/v1/agents/" + URLEncoder.encode(agentId, StandardCharsets.UTF_8) + "/audit";
        if (params != null) {
            path = appendAuditParams(path, params);
        }

        HttpRequest request = createRequestBuilder(path).GET().build();
        HttpResponse<String> response = sendRequest(request);

        try {
            TransparencyLogAudit audit = objectMapper.readValue(
                response.body(), TransparencyLogAudit.class);

            // Parse payloads for each record
            if (audit.getRecords() != null) {
                for (TransparencyLog record : audit.getRecords()) {
                    parseAndSetPayload(record, record.getSchemaVersion());
                }
            }

            return audit;
        } catch (IOException e) {
            throw new AnsServerException("Failed to parse audit response: " + e.getMessage(), 0, e, null);
        }
    }

    /**
     * Gets the current checkpoint.
     */
    CheckpointResponse getCheckpoint() {
        HttpRequest request = createRequestBuilder("/v1/log/checkpoint").GET().build();
        HttpResponse<String> response = sendRequest(request);

        try {
            return objectMapper.readValue(response.body(), CheckpointResponse.class);
        } catch (IOException e) {
            throw new AnsServerException("Failed to parse checkpoint response: " + e.getMessage(), 0, e, null);
        }
    }

    /**
     * Gets checkpoint history.
     */
    CheckpointHistoryResponse getCheckpointHistory(CheckpointHistoryParams params) {
        String path = "/v1/log/checkpoint/history";
        if (params != null) {
            path = appendCheckpointHistoryParams(path, params);
        }

        HttpRequest request = createRequestBuilder(path).GET().build();
        HttpResponse<String> response = sendRequest(request);

        try {
            return objectMapper.readValue(response.body(), CheckpointHistoryResponse.class);
        } catch (IOException e) {
            throw new AnsServerException(
                "Failed to parse checkpoint history response: " + e.getMessage(), 0, e, null);
        }
    }

    /**
     * Gets the JSON schema for a version.
     */
    @SuppressWarnings("unchecked")
    Map<String, Object> getLogSchema(String version) {
        String path = "/v1/log/schema/" + URLEncoder.encode(version, StandardCharsets.UTF_8);
        HttpRequest request = createRequestBuilder(path).GET().build();
        HttpResponse<String> response = sendRequest(request);

        try {
            return objectMapper.readValue(response.body(), Map.class);
        } catch (IOException e) {
            throw new AnsServerException("Failed to parse schema response: " + e.getMessage(), 0, e, null);
        }
    }

    /**
     * Gets the SCITT receipt for an agent.
     *
     * @param agentId the agent's unique identifier
     * @return the raw receipt bytes (COSE_Sign1)
     */
    byte[] getReceipt(String agentId) {
        String path = "/v1/agents/" + URLEncoder.encode(agentId, StandardCharsets.UTF_8) + "/receipt";
        return fetchBinaryResponse(path, "application/scitt-receipt+cose");
    }

    /**
     * Gets the status token for an agent.
     *
     * @param agentId the agent's unique identifier
     * @return the raw status token bytes (COSE_Sign1)
     */
    byte[] getStatusToken(String agentId) {
        String path = "/v1/agents/" + URLEncoder.encode(agentId, StandardCharsets.UTF_8) + "/status-token";
        return fetchBinaryResponse(path, "application/ans-status-token+cbor");
    }

    /**
     * Gets the SCITT receipt for an agent asynchronously using non-blocking I/O.
     *
     * @param agentId the agent's unique identifier
     * @return a CompletableFuture with the raw receipt bytes (COSE_Sign1)
     */
    CompletableFuture<byte[]> getReceiptAsync(String agentId) {
        String path = "/v1/agents/" + URLEncoder.encode(agentId, StandardCharsets.UTF_8) + "/receipt";
        return fetchBinaryResponseAsync(path, "application/scitt-receipt+cose");
    }

    /**
     * Gets the status token for an agent asynchronously using non-blocking I/O.
     *
     * @param agentId the agent's unique identifier
     * @return a CompletableFuture with the raw status token bytes (COSE_Sign1)
     */
    CompletableFuture<byte[]> getStatusTokenAsync(String agentId) {
        String path = "/v1/agents/" + URLEncoder.encode(agentId, StandardCharsets.UTF_8) + "/status-token";
        return fetchBinaryResponseAsync(path, "application/ans-status-token+cbor");
    }

    /**
     * Returns the SCITT root public keys asynchronously, using cached values if available.
     *
     * <p>The root keys are cached with a configurable TTL to avoid redundant
     * network calls on every verification request. Concurrent callers share
     * a single in-flight fetch to prevent cache stampedes.</p>
     *
     * <p>The returned map is keyed by hex key ID (4-byte SHA-256 of SPKI-DER),
     * enabling O(1) lookup by key ID from COSE headers.</p>
     *
     * @return a CompletableFuture with the root public keys for verifying receipts and status tokens
     */
    CompletableFuture<Map<String, PublicKey>> getRootKeysAsync() {
        return rootKeyManager.getRootKeysAsync();
    }

    /**
     * Invalidates the cached root key, forcing the next call to fetch from the server.
     */
    void invalidateRootKeyCache() {
        rootKeyManager.invalidateRootKeyCache();
    }

    /**
     * Returns the timestamp when the root key cache was last populated.
     *
     * @return the cache population timestamp, or {@link Instant#EPOCH} if never populated
     */
    Instant getCachePopulatedAt() {
        return rootKeyManager.getCachePopulatedAt();
    }

    /**
     * Attempts to refresh the root key cache if the artifact's issued-at timestamp
     * indicates it may have been signed with a new key not yet in our cache.
     *
     * <p>Security checks performed:</p>
     * <ol>
     *   <li>Reject artifacts claiming to be from the future (beyond clock skew tolerance)</li>
     *   <li>Reject artifacts older than our cache (key should already be present)</li>
     *   <li>Enforce global cooldown to prevent cache thrashing attacks</li>
     * </ol>
     *
     * @param artifactIssuedAt the issued-at timestamp from the SCITT artifact
     * @return a future containing the refresh decision with action, reason, and optionally refreshed keys
     */
    CompletableFuture<RefreshDecision> refreshRootKeysIfNeeded(Instant artifactIssuedAt) {
        return rootKeyManager.refreshRootKeysIfNeeded(artifactIssuedAt);
    }

    @Override
    public void close() {
        httpClient.executor().ifPresent(e -> {
            if (e instanceof java.util.concurrent.ExecutorService es) {
                es.shutdown();
            }
        });
    }

    /**
     * Fetches a binary response from the API.
     */
    private byte[] fetchBinaryResponse(String path, String acceptHeader) {
        HttpRequest request = buildBinaryRequest(path, acceptHeader);

        try {
            HttpResponse<byte[]> response = httpClient.send(
                request, HttpResponse.BodyHandlers.ofByteArray());
            String requestId = response.headers().firstValue("X-Request-Id").orElse(null);
            String body = new String(response.body(), StandardCharsets.UTF_8);
            throwForStatus(response.statusCode(), body, requestId);
            return response.body();
        } catch (IOException e) {
            throw new AnsServerException("Network error: " + e.getMessage(), 0, e, null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AnsServerException("Request interrupted", 0, e, null);
        }
    }

    /**
     * Fetches a binary response from the API asynchronously using non-blocking I/O.
     */
    private CompletableFuture<byte[]> fetchBinaryResponseAsync(String path, String acceptHeader) {
        HttpRequest request = buildBinaryRequest(path, acceptHeader);

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofByteArray())
            .thenApply(response -> {
                String requestId = response.headers().firstValue("X-Request-Id").orElse(null);
                String body = new String(response.body(), StandardCharsets.UTF_8);
                throwForStatus(response.statusCode(), body, requestId);
                return response.body();
            });
    }

    /**
     * Builds an HTTP request for binary content.
     */
    private HttpRequest buildBinaryRequest(String path, String acceptHeader) {
        return HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + path))
            .header("Accept", acceptHeader)
            .timeout(readTimeout)
            .GET()
            .build();
    }

    /**
     * Fetches a transparency log entry with schema version handling.
     */
    private TransparencyLog fetchWithSchemaVersion(String path) {
        HttpRequest request = createRequestBuilder(path).GET().build();

        try {
            HttpResponse<String> response = httpClient.send(
                request, HttpResponse.BodyHandlers.ofString());
            handleErrorResponse(response);

            // Parse base response
            TransparencyLog result = objectMapper.readValue(response.body(), TransparencyLog.class);

            // Get schema version from header if not in response body
            String schemaVersion = result.getSchemaVersion();
            if (schemaVersion == null || schemaVersion.isEmpty()) {
                schemaVersion = response.headers()
                    .firstValue(SCHEMA_VERSION_HEADER)
                    .orElse("V0");
                result.setSchemaVersion(schemaVersion);
            }

            // Parse payload based on schema version
            parseAndSetPayload(result, schemaVersion);

            return result;
        } catch (IOException e) {
            throw new AnsServerException("Network error: " + e.getMessage(), 0, e, null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AnsServerException("Request interrupted", 0, e, null);
        }
    }

    /**
     * Parses the payload and sets the parsed payload on the result.
     */
    private void parseAndSetPayload(TransparencyLog result, String schemaVersion) {
        if (result.getPayload() == null) {
            return;
        }

        try {
            if ("V1".equalsIgnoreCase(schemaVersion)) {
                TransparencyLogV1 v1 = objectMapper.convertValue(result.getPayload(), TransparencyLogV1.class);
                result.setParsedPayload(v1);
            } else {
                // V0 is default for missing or unknown schema version
                TransparencyLogV0 v0 = objectMapper.convertValue(result.getPayload(), TransparencyLogV0.class);
                result.setParsedPayload(v0);
            }
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Failed to parse {} payload: {}", schemaVersion, e.getMessage());
        }
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
        String requestId = response.headers().firstValue("X-Request-Id").orElse(null);
        throwForStatus(response.statusCode(), response.body(), requestId);
    }

    /**
     * Throws an appropriate exception for non-success HTTP status codes.
     *
     * @param statusCode the HTTP status code
     * @param body the response body as a string
     * @param requestId the request ID from headers, may be null
     */
    private void throwForStatus(int statusCode, String body, String requestId) {
        if (statusCode >= 200 && statusCode < 300) {
            return; // Success
        }

        if (statusCode == 404) {
            throw new AnsNotFoundException("Resource not found: " + body, null, null, requestId);
        } else if (statusCode >= 500) {
            throw new AnsServerException("Server error: " + body, statusCode, requestId);
        } else {
            throw new AnsServerException(
                "Unexpected error (" + statusCode + "): " + body, statusCode, requestId);
        }
    }

    /**
     * Creates a request builder with common headers.
     */
    private HttpRequest.Builder createRequestBuilder(String path) {
        return HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + path))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .timeout(readTimeout);
    }

    /**
     * Appends audit parameters to the path.
     */
    private String appendAuditParams(String path, AgentAuditParams params) {
        QueryParamBuilder builder = new QueryParamBuilder();
        builder.addIfPositive("offset", params.getOffset());
        builder.addIfPositive("limit", params.getLimit());
        return builder.buildUrl(path);
    }

    /**
     * Appends checkpoint history parameters to the path.
     */
    private String appendCheckpointHistoryParams(String path, CheckpointHistoryParams params) {
        QueryParamBuilder builder = new QueryParamBuilder();
        builder.addIfPositive("limit", params.getLimit());
        builder.addIfPositive("offset", params.getOffset());
        builder.addIfPositive("fromSize", params.getFromSize());
        builder.addIfPositive("toSize", params.getToSize());
        if (params.getSince() != null) {
            String since = params.getSince().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
            builder.addEncoded("since", since);
        }
        builder.addEncodedIfNotEmpty("order", params.getOrder());
        return builder.buildUrl(path);
    }

    /**
     * Helper for building URL query strings.
     */
    private static final class QueryParamBuilder {
        private final StringJoiner joiner = new StringJoiner("&");

        /**
         * Adds a parameter if the value is positive.
         */
        void addIfPositive(String name, long value) {
            if (value > 0) {
                joiner.add(name + "=" + value);
            }
        }

        /**
         * Adds a URL-encoded parameter.
         */
        void addEncoded(String name, String value) {
            joiner.add(name + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8));
        }

        /**
         * Adds a URL-encoded parameter if the value is not null or empty.
         */
        void addEncodedIfNotEmpty(String name, String value) {
            if (value != null && !value.isEmpty()) {
                addEncoded(name, value);
            }
        }

        /**
         * Builds the final URL with query string.
         */
        String buildUrl(String path) {
            if (joiner.length() > 0) {
                return path + "?" + joiner;
            }
            return path;
        }
    }
}