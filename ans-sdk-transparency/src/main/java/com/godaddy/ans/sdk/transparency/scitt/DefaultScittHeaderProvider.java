package com.godaddy.ans.sdk.transparency.scitt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Default implementation of {@link ScittHeaderProvider}.
 *
 * <p>Handles Base64 encoding/decoding of SCITT artifacts for HTTP header transport.</p>
 */
public class DefaultScittHeaderProvider implements ScittHeaderProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultScittHeaderProvider.class);

    private final byte[] ownReceiptBytes;
    private final byte[] ownTokenBytes;
    // Pre-computed headers to avoid Base64 encoding on every getOutgoingHeaders() call
    private final Map<String, String> cachedOutgoingHeaders;

    /**
     * Creates a provider without own artifacts (client-only mode).
     *
     * <p>Use this when only extracting SCITT artifacts from responses,
     * not including them in requests.</p>
     */
    public DefaultScittHeaderProvider() {
        this(null, null);
    }

    /**
     * Creates a provider with own SCITT artifacts.
     *
     * @param ownReceiptBytes the caller's receipt bytes (may be null)
     * @param ownTokenBytes the caller's status token bytes (may be null)
     */
    public DefaultScittHeaderProvider(byte[] ownReceiptBytes, byte[] ownTokenBytes) {
        this.ownReceiptBytes = ownReceiptBytes != null ? ownReceiptBytes.clone() : null;
        this.ownTokenBytes = ownTokenBytes != null ? ownTokenBytes.clone() : null;
        this.cachedOutgoingHeaders = buildOutgoingHeaders();
    }

    /**
     * Builds and caches the outgoing headers at construction time.
     * Base64 encoding happens once, not on every getOutgoingHeaders() call.
     */
    private Map<String, String> buildOutgoingHeaders() {
        if (ownReceiptBytes == null && ownTokenBytes == null) {
            return Collections.emptyMap();
        }

        Map<String, String> headers = new HashMap<>();

        if (ownReceiptBytes != null) {
            headers.put(ScittHeaders.SCITT_RECEIPT_HEADER,
                Base64.getEncoder().encodeToString(ownReceiptBytes));
        }

        if (ownTokenBytes != null) {
            headers.put(ScittHeaders.STATUS_TOKEN_HEADER,
                Base64.getEncoder().encodeToString(ownTokenBytes));
        }

        return Collections.unmodifiableMap(headers);
    }

    @Override
    public Map<String, String> getOutgoingHeaders() {
        return cachedOutgoingHeaders;
    }

    @Override
    public Optional<ScittArtifacts> extractArtifacts(Map<String, String> headers) {
        Objects.requireNonNull(headers, "headers cannot be null");

        String receiptHeader = headers.get(ScittHeaders.SCITT_RECEIPT_HEADER);
        String tokenHeader = headers.get(ScittHeaders.STATUS_TOKEN_HEADER);

        if (receiptHeader == null && tokenHeader == null) {
            LOGGER.debug("No SCITT headers present in response");
            return Optional.empty();
        }

        byte[] receiptBytes = null;
        byte[] tokenBytes = null;
        ScittReceipt receipt = null;
        StatusToken statusToken = null;
        List<String> parseErrors = new ArrayList<>();

        // Parse receipt
        if (receiptHeader != null) {
            try {
                receiptBytes = Base64.getDecoder().decode(receiptHeader);
                receipt = ScittReceipt.parse(receiptBytes);
                LOGGER.debug("Parsed SCITT receipt ({} bytes)", receiptBytes.length);
            } catch (IllegalArgumentException e) {
                String error = "Invalid Base64 in receipt header: " + e.getMessage();
                LOGGER.warn(error);
                parseErrors.add(error);
            } catch (ScittParseException e) {
                String error = "Failed to parse receipt: " + e.getMessage();
                LOGGER.warn(error);
                parseErrors.add(error);
            }
        }

        // Parse status token
        if (tokenHeader != null) {
            try {
                tokenBytes = Base64.getDecoder().decode(tokenHeader);
                statusToken = StatusToken.parse(tokenBytes);
                LOGGER.debug("Parsed status token for agent {} ({} bytes)",
                    statusToken.agentId(), tokenBytes.length);
            } catch (IllegalArgumentException e) {
                String error = "Invalid Base64 in status token header: " + e.getMessage();
                LOGGER.warn(error);
                parseErrors.add(error);
            } catch (ScittParseException e) {
                String error = "Failed to parse status token: " + e.getMessage();
                LOGGER.warn(error);
                parseErrors.add(error);
            }
        }

        if (receipt == null || statusToken == null) {
            // Headers were present but failed to parse
            String errorDetail = String.join("; ", parseErrors);
            LOGGER.error("SCITT headers present but artifacts failed to parse: {}", errorDetail);
            return Optional.empty();
        }

        return Optional.of(new ScittArtifacts(receipt, statusToken));
    }

    /**
     * Builder for creating DefaultScittHeaderProvider instances.
     */
    public static class Builder {
        private byte[] receiptBytes;
        private byte[] tokenBytes;

        /**
         * Sets the caller's SCITT receipt bytes.
         *
         * @param receiptBytes the receipt bytes
         * @return this builder
         */
        public Builder receipt(byte[] receiptBytes) {
            this.receiptBytes = receiptBytes;
            return this;
        }

        /**
         * Sets the caller's status token bytes.
         *
         * @param tokenBytes the token bytes
         * @return this builder
         */
        public Builder statusToken(byte[] tokenBytes) {
            this.tokenBytes = tokenBytes;
            return this;
        }

        /**
         * Builds the header provider.
         *
         * @return the configured provider
         */
        public DefaultScittHeaderProvider build() {
            return new DefaultScittHeaderProvider(receiptBytes, tokenBytes);
        }
    }

    /**
     * Creates a new builder.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }
}
