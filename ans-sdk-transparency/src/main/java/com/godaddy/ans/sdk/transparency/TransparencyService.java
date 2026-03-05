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

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.StringJoiner;

/**
 * Internal service for handling transparency log API calls.
 */
class TransparencyService {

    private static final String SCHEMA_VERSION_HEADER = "X-Schema-Version";

    private final String baseUrl;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Duration readTimeout;

    TransparencyService(String baseUrl, Duration connectTimeout, Duration readTimeout) {
        this.baseUrl = baseUrl;
        this.readTimeout = readTimeout;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(connectTimeout)
            .followRedirects(HttpClient.Redirect.NORMAL)
            .version(HttpClient.Version.HTTP_1_1)
            .build();
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        this.objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
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
            String payloadJson = objectMapper.writeValueAsString(result.getPayload());

            if ("V1".equalsIgnoreCase(schemaVersion)) {
                TransparencyLogV1 v1 = objectMapper.readValue(payloadJson, TransparencyLogV1.class);
                result.setParsedPayload(v1);
            } else {
                // V0 is default for missing or unknown schema version
                TransparencyLogV0 v0 = objectMapper.readValue(payloadJson, TransparencyLogV0.class);
                result.setParsedPayload(v0);
            }
        } catch (IOException e) {
            // If parsing fails, leave parsedPayload as null
            // The raw payload is still available
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
        int statusCode = response.statusCode();

        if (statusCode >= 200 && statusCode < 300) {
            return; // Success
        }

        String requestId = response.headers().firstValue("X-Request-Id").orElse(null);
        String body = response.body();

        if (statusCode == 404) {
            throw new AnsNotFoundException("Agent not found: " + body, null, null, requestId);
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
        StringJoiner joiner = new StringJoiner("&");
        if (params.getOffset() > 0) {
            joiner.add("offset=" + params.getOffset());
        }
        if (params.getLimit() > 0) {
            joiner.add("limit=" + params.getLimit());
        }
        if (joiner.length() > 0) {
            return path + "?" + joiner;
        }
        return path;
    }

    /**
     * Appends checkpoint history parameters to the path.
     */
    private String appendCheckpointHistoryParams(String path, CheckpointHistoryParams params) {
        StringJoiner joiner = new StringJoiner("&");
        if (params.getLimit() > 0) {
            joiner.add("limit=" + params.getLimit());
        }
        if (params.getOffset() > 0) {
            joiner.add("offset=" + params.getOffset());
        }
        if (params.getFromSize() > 0) {
            joiner.add("fromSize=" + params.getFromSize());
        }
        if (params.getToSize() > 0) {
            joiner.add("toSize=" + params.getToSize());
        }
        if (params.getSince() != null) {
            String since = params.getSince().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
            joiner.add("since=" + URLEncoder.encode(since, StandardCharsets.UTF_8));
        }
        if (params.getOrder() != null && !params.getOrder().isEmpty()) {
            joiner.add("order=" + URLEncoder.encode(params.getOrder(), StandardCharsets.UTF_8));
        }
        if (joiner.length() > 0) {
            return path + "?" + joiner;
        }
        return path;
    }
}