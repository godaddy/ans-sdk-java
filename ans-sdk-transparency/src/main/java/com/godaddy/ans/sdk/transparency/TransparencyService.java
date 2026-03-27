package com.godaddy.ans.sdk.transparency;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.benmanes.caffeine.cache.AsyncLoadingCache;
import com.github.benmanes.caffeine.cache.Caffeine;
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

import com.godaddy.ans.sdk.crypto.CryptoCache;

import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Internal service for handling transparency log API calls.
 */
class TransparencyService {

    private static final Logger LOGGER = LoggerFactory.getLogger(TransparencyService.class);
    private static final String SCHEMA_VERSION_HEADER = "X-Schema-Version";

    private static final String ROOT_KEY_CACHE_KEY = "root";

    /**
     * Maximum number of root keys to cache. Prevents DoS from unbounded key sets.
     */
    private static final int MAX_ROOT_KEYS = 20;

    /**
     * Global cooldown between cache refresh attempts to prevent cache thrashing.
     */
    private static final Duration REFRESH_COOLDOWN = Duration.ofSeconds(30);

    /**
     * Maximum tolerance for artifact timestamps in the future (clock skew).
     */
    private static final Duration FUTURE_TOLERANCE = Duration.ofSeconds(60);

    /**
     * Tolerance for artifacts issued slightly before cache refresh (race conditions).
     */
    private static final Duration PAST_TOLERANCE = Duration.ofMinutes(5);

    /**
     * Cached KeyFactory instance. Thread-safe after initialization.
     */
    private static final KeyFactory EC_KEY_FACTORY;

    static {
        try {
            EC_KEY_FACTORY = KeyFactory.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("EC algorithm not available", e);
        }
    }

    private final String baseUrl;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Duration readTimeout;

    // Root keys cache with automatic TTL and stampede prevention (keyed by hex key ID)
    private final AsyncLoadingCache<String, Map<String, PublicKey>> rootKeyCache;

    // Timestamp when cache was last populated (for refresh-on-miss logic)
    private final AtomicReference<Instant> cachePopulatedAt = new AtomicReference<>(Instant.EPOCH);

    // Timestamp of last refresh attempt (for cooldown enforcement)
    private final AtomicReference<Instant> lastRefreshAttempt = new AtomicReference<>(Instant.EPOCH);

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

        // Build root keys cache with TTL - stampede prevention is automatic
        this.rootKeyCache = Caffeine.newBuilder()
            .maximumSize(1)
            .expireAfterWrite(rootKeyCacheTtl)
            .buildAsync((key, executor) -> fetchRootKeysFromServerAsync());
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
        return rootKeyCache.get(ROOT_KEY_CACHE_KEY);
    }

    /**
     * Invalidates the cached root key, forcing the next call to fetch from the server.
     */
    void invalidateRootKeyCache() {
        rootKeyCache.synchronous().invalidate(ROOT_KEY_CACHE_KEY);
        LOGGER.debug("Root key cache invalidated");
    }

    /**
     * Returns the timestamp when the root key cache was last populated.
     *
     * @return the cache population timestamp, or {@link Instant#EPOCH} if never populated
     */
    Instant getCachePopulatedAt() {
        return cachePopulatedAt.get();
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
     * @return the refresh decision with action, reason, and optionally refreshed keys
     */
    RefreshDecision refreshRootKeysIfNeeded(Instant artifactIssuedAt) {
        Instant now = Instant.now();
        Instant cacheTime = cachePopulatedAt.get();

        // Check 1: Reject artifacts from the future (beyond clock skew tolerance)
        if (artifactIssuedAt.isAfter(now.plus(FUTURE_TOLERANCE))) {
            LOGGER.warn("Artifact timestamp {} is in the future (now={}), rejecting",
                artifactIssuedAt, now);
            return RefreshDecision.reject("Artifact timestamp is in the future");
        }

        // Check 2: Reject artifacts older than cache (with past tolerance for race conditions)
        // If artifact was issued before we refreshed cache, the key SHOULD be there
        if (artifactIssuedAt.isBefore(cacheTime.minus(PAST_TOLERANCE))) {
            LOGGER.debug("Artifact issued at {} predates cache refresh at {} (with {}min tolerance), "
                + "key should be present - rejecting refresh",
                artifactIssuedAt, cacheTime, PAST_TOLERANCE.toMinutes());
            return RefreshDecision.reject(
                "Key not found and artifact predates cache refresh");
        }

        // Check 3: Enforce global cooldown to prevent cache thrashing
        Instant lastAttempt = lastRefreshAttempt.get();
        if (lastAttempt.plus(REFRESH_COOLDOWN).isAfter(now)) {
            Duration remaining = Duration.between(now, lastAttempt.plus(REFRESH_COOLDOWN));
            LOGGER.debug("Cache refresh on cooldown, {} remaining", remaining);
            return RefreshDecision.defer(
                "Cache was recently refreshed, retry in " + remaining.toSeconds() + "s");
        }

        // All checks passed - attempt refresh
        LOGGER.info("Artifact issued at {} is newer than cache at {}, refreshing root keys",
            artifactIssuedAt, cacheTime);

        // Update cooldown timestamp before fetch to prevent concurrent refresh attempts
        lastRefreshAttempt.set(now);

        try {
            // Invalidate and fetch fresh keys
            invalidateRootKeyCache();
            Map<String, PublicKey> freshKeys = getRootKeysAsync().join();
            LOGGER.info("Cache refresh complete, now have {} keys", freshKeys.size());
            return RefreshDecision.refreshed(freshKeys);
        } catch (Exception e) {
            LOGGER.error("Failed to refresh root keys: {}", e.getMessage());
            return RefreshDecision.defer("Failed to refresh: " + e.getMessage());
        }
    }

    /**
     * Fetches the SCITT root public keys from the /root-keys endpoint asynchronously.
     */
    private CompletableFuture<Map<String, PublicKey>> fetchRootKeysFromServerAsync() {
        LOGGER.info("Fetching root keys from server");
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/root-keys"))
            .header("Accept", "application/json")
            .timeout(readTimeout)
            .GET()
            .build();

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
            .thenApply(response -> {
                if (response.statusCode() != 200) {
                    throw new AnsServerException(
                        "Failed to fetch root keys: HTTP " + response.statusCode(),
                        response.statusCode(),
                        response.headers().firstValue("X-Request-Id").orElse(null));
                }
                Map<String, PublicKey> keys = parsePublicKeysResponse(response.body());
                cachePopulatedAt.set(Instant.now());
                LOGGER.info("Fetched and cached {} root key(s) at {}", keys.size(), cachePopulatedAt.get());
                return keys;
            });
    }

    /**
     * Parses public keys from the root-keys API response.
     *
     * <p>Format is C2SP note: each line is {@code name+key_hash+base64_public_key}</p>
     * <p>Example:</p>
     * <pre>
     * transparency.ans.godaddy.com+bb7ed8cf+AjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IAB...
     * transparency.ans.godaddy.com+cc8fe9d0+AjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IAB...
     * </pre>
     *
     * <p>Returns a map keyed by hex key ID (4-byte SHA-256 of SPKI-DER) for O(1) lookup.</p>
     *
     * @param responseBody the raw response body (text/plain, C2SP note format)
     * @return map of hex key ID to public key
     * @throws IllegalArgumentException if no valid keys found or too many keys
     */
    private Map<String, PublicKey> parsePublicKeysResponse(String responseBody) {
        Map<String, PublicKey> keys = new HashMap<>();
        List<String> parseErrors = new ArrayList<>();

        String[] lines = responseBody.split("\n");
        int lineNum = 0;
        for (String line : lines) {
            lineNum++;
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            // Check max keys limit
            if (keys.size() >= MAX_ROOT_KEYS) {
                LOGGER.warn("Reached max root keys limit ({}), ignoring remaining keys", MAX_ROOT_KEYS);
                break;
            }

            // C2SP format: name+key_hash+base64_key (limit split to 3 since base64 can contain '+')
            String[] parts = line.split("\\+", 3);
            if (parts.length != 3) {
                String error = String.format("Line %d: expected C2SP format (name+hash+key), got %d parts",
                    lineNum, parts.length);
                LOGGER.debug("Public key parse failed - {}", error);
                parseErrors.add(error);
                continue;
            }

            try {
                PublicKey key = decodePublicKey(parts[2].trim());
                String hexKeyId = computeHexKeyId(key);
                if (keys.containsKey(hexKeyId)) {
                    LOGGER.warn("Duplicate key ID {} at line {}, skipping", hexKeyId, lineNum);
                } else {
                    keys.put(hexKeyId, key);
                    LOGGER.debug("Parsed key with ID {} at line {}", hexKeyId, lineNum);
                }
            } catch (Exception e) {
                String error = String.format("Line %d: %s", lineNum, e.getMessage());
                LOGGER.debug("Public key parse failed - {}", error);
                parseErrors.add(error);
            }
        }

        if (keys.isEmpty()) {
            String errorDetail = parseErrors.isEmpty()
                ? "No parseable key lines found"
                : "Parse attempts failed: " + String.join("; ", parseErrors);
            throw new IllegalArgumentException("Could not parse any public keys from response. " + errorDetail);
        }

        return keys;
    }

    /**
     * Computes the hex key ID for a public key per C2SP specification.
     *
     * <p>The key ID is the first 4 bytes of SHA-256(SPKI-DER), where SPKI-DER
     * is the Subject Public Key Info DER encoding of the public key.</p>
     *
     * @param publicKey the public key
     * @return the 8-character hex key ID
     */
    static String computeHexKeyId(PublicKey publicKey) {
        byte[] spkiDer = publicKey.getEncoded();
        byte[] hash = CryptoCache.sha256(spkiDer);
        return Hex.toHexString(Arrays.copyOf(hash, 4));
    }

    /**
     * Decodes a base64-encoded public key.
     */
    private PublicKey decodePublicKey(String base64Key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);

        // C2SP note format includes a version byte prefix (0x02) before the SPKI-DER data.
        // We need to strip it to get valid SPKI-DER for Java's KeyFactory.
        // Detection: SPKI-DER starts with 0x30 (SEQUENCE tag), C2SP prefixed data starts with 0x02.
        if (keyBytes.length > 0 && keyBytes[0] == 0x02) {
            // Strip C2SP version byte (first byte)
            keyBytes = Arrays.copyOfRange(keyBytes, 1, keyBytes.length);
        }

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return EC_KEY_FACTORY.generatePublic(keySpec);
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
            // If conversion fails, leave parsedPayload as null
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