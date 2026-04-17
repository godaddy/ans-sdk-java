package com.godaddy.ans.sdk.agent.verification;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TLSARecord;
import org.xbill.DNS.Type;
import org.xbill.DNS.dnssec.ValidatingResolver;
import org.xbill.DNS.lookup.LookupResult;
import org.xbill.DNS.lookup.LookupSession;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Default implementation of DANE/TLSA verification using dnsjava.
 *
 * <p>This verifier queries DNS for TLSA records and compares them against
 * the server's TLS certificate. It supports two DNSSEC validation modes:</p>
 *
 * <h2>DNSSEC Validation Modes</h2>
 * <ul>
 *   <li><b>TRUST_RESOLVER</b>: Relies on upstream resolver (Cloudflare, Google) to validate DNSSEC.
 *       Checks the AD (Authenticated Data) flag in responses.</li>
 *   <li><b>VALIDATE_IN_CODE</b>: Performs DNSSEC validation locally using dnsjava's ValidatingResolver.
 *       Works with any resolver, including non-DNSSEC ones.</li>
 * </ul>
 *
 * <h2>TLSA Record Format</h2>
 * <p>TLSA records are published at {@code _port._tcp.hostname} with format:</p>
 * <pre>
 * Usage Selector MatchingType CertificateAssociationData
 * </pre>
 *
 * <p>Common configurations:</p>
 * <ul>
 *   <li><b>3 1 1</b>: Domain-issued cert, SPKI (public key), SHA-256 hash</li>
 *   <li><b>3 0 1</b>: Domain-issued cert, Full cert, SHA-256 hash</li>
 * </ul>
 *
 * <h2>Usage Example</h2>
 * <pre>{@code
 * // Default configuration (opportunistic DANE with Cloudflare DNS, trust resolver)
 * DaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(DaneConfig.defaults());
 *
 * // In-code DNSSEC validation (works with any resolver)
 * DaneConfig config = DaneConfig.builder()
 *     .policy(DanePolicy.REQUIRED)
 *     .resolver(DnsResolverConfig.SYSTEM)
 *     .validationMode(DnssecValidationMode.VALIDATE_IN_CODE)
 *     .build();
 * DaneTlsaVerifier strictVerifier = new DefaultDaneTlsaVerifier(config);
 *
 * // Check if TLSA record exists (with DNSSEC validation)
 * if (verifier.hasTlsaRecord("example.com", 443)) {
 *     TlsaResult result = verifier.verifyTlsa("example.com", 443);
 *     if (result.verified()) {
 *         System.out.println("DANE verified: " + result.matchType());
 *     }
 * }
 * }</pre>
 */
public class DefaultDaneTlsaVerifier implements DaneTlsaVerifier {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultDaneTlsaVerifier.class);

    // Import TLSA constants from TlsaUtils for local use
    private static final int SELECTOR_FULL_CERT = TlsaUtils.SELECTOR_FULL_CERT;
    private static final int SELECTOR_SPKI = TlsaUtils.SELECTOR_SPKI;
    private static final int MATCH_SHA256 = TlsaUtils.MATCH_SHA256;
    private static final int MATCH_SHA512 = TlsaUtils.MATCH_SHA512;

    /**
     * Default fallback DNS server for DNSSEC validation.
     */
    public static final String DEFAULT_DNSSEC_RESOLVER = "1.1.1.1";

    private final DanePolicy policy;
    private final DnssecValidationMode validationMode;
    private final String dnsServer;
    private final int connectTimeout;
    private final Duration cacheTtl;
    private final ConcurrentHashMap<String, CachedTlsaRecords> tlsaCache = new ConcurrentHashMap<>();
    private final ResolverFactory resolverFactory;
    private final CertificateFetcher certificateFetcher;

    /**
     * Creates a verifier with the specified configuration.
     *
     * @param config the DANE configuration
     */
    public DefaultDaneTlsaVerifier(DaneConfig config) {
        this(config, ResolverFactory.defaultFactory(), CertificateFetcher.defaultFetcher());
    }

    /**
     * Creates a verifier with the specified configuration and custom factories.
     *
     * <p>This constructor allows injection of custom factories for testing purposes.</p>
     *
     * @param config the DANE configuration
     * @param resolverFactory factory for creating DNS resolvers
     * @param certificateFetcher fetcher for server certificates
     */
    public DefaultDaneTlsaVerifier(DaneConfig config, ResolverFactory resolverFactory,
                                   CertificateFetcher certificateFetcher) {
        this.policy = config.policy();
        this.validationMode = config.validationMode();
        this.dnsServer = config.resolver().isSystemResolver()
            ? null
            : config.resolver().getPrimaryAddress();
        this.connectTimeout = 10000;
        this.cacheTtl = config.cacheTtl();
        this.resolverFactory = resolverFactory;
        this.certificateFetcher = certificateFetcher;
    }

    @Override
    public TlsaResult verifyTlsa(String hostname, int port) {
        // Check policy first
        if (policy == DanePolicy.DISABLED) {
            LOGGER.debug("DANE verification disabled, skipping for {}:{}", hostname, port);
            return TlsaResult.skipped("DANE verification disabled");
        }

        LOGGER.debug("Verifying TLSA for {}:{} (validationMode={}, policy={})",
            hostname, port, validationMode, policy);

        // Step 1: Query ALL TLSA records from DNS with DNSSEC validation
        List<TlsaRecordData> tlsaRecords;
        try {
            tlsaRecords = queryTlsaRecords(hostname, port);
            if (tlsaRecords.isEmpty()) {
                if (policy == DanePolicy.REQUIRED) {
                    LOGGER.warn("TLSA record required but not found for {}:{}", hostname, port);
                    return TlsaResult.failure("TLSA record required but not found");
                }
                return TlsaResult.noRecord();
            }
            LOGGER.debug("Found {} DNSSEC-validated TLSA record(s) for {}", tlsaRecords.size(), hostname);
        } catch (DnssecValidationException e) {
            LOGGER.warn("DNSSEC validation failed for {}: {}", hostname, e.getMessage());
            return TlsaResult.failure("DNSSEC validation failed: " + e.getMessage());
        } catch (Exception e) {
            LOGGER.warn("Failed to query TLSA records for {}: {}", hostname, e.getMessage());
            return TlsaResult.failure("DNS query failed: " + e.getMessage());
        }

        // Step 2: Get server certificate
        X509Certificate serverCert;
        try {
            serverCert = getServerCertificate(hostname, port);
            LOGGER.debug("Retrieved server certificate: {}", serverCert.getSubjectX500Principal());
        } catch (Exception e) {
            LOGGER.warn("Failed to get server certificate for {}:{}: {}", hostname, port, e.getMessage());
            return TlsaResult.failure("Certificate retrieval failed: " + e.getMessage());
        }

        // Step 3: Try to match certificate against ANY TLSA record
        // This supports certificate rotation where multiple TLSA records may exist
        String lastMismatchReason = null;
        for (TlsaRecordData tlsaRecord : tlsaRecords) {
            try {
                byte[] certData = TlsaUtils.computeCertificateData(serverCert, tlsaRecord.selector,
                        tlsaRecord.matchingType);
                if (MessageDigest.isEqual(certData, tlsaRecord.certificateData)) {
                    String matchType = TlsaUtils.describeMatchType(tlsaRecord.selector, tlsaRecord.matchingType);
                    LOGGER.debug("TLSA match found: {} (record {} of {})",
                        matchType, tlsaRecords.indexOf(tlsaRecord) + 1, tlsaRecords.size());
                    return TlsaResult.success(matchType, certData);
                } else {
                    String actualHash = TlsaUtils.bytesToHex(certData);
                    String expectedHash = TlsaUtils.bytesToHex(tlsaRecord.certificateData);
                    LOGGER.debug("TLSA record {} did not match: expected={}, actual={}",
                        tlsaRecords.indexOf(tlsaRecord) + 1, expectedHash, actualHash);
                    lastMismatchReason = "Certificate does not match TLSA record";
                }
            } catch (Exception e) {
                LOGGER.debug("Error matching TLSA record {}: {}", tlsaRecords.indexOf(tlsaRecord) + 1, e.getMessage());
                lastMismatchReason = "Error matching certificate: " + e.getMessage();
            }
        }

        // No matching TLSA record found
        LOGGER.warn("Certificate did not match any of {} TLSA record(s) for {}:{}", tlsaRecords.size(), hostname, port);
        return TlsaResult.failure(lastMismatchReason != null ? lastMismatchReason : "No matching TLSA record");
    }

    @Override
    public boolean hasTlsaRecord(String hostname, int port) {
        if (policy == DanePolicy.DISABLED) {
            return false;
        }

        try {
            List<TlsaRecordData> records = queryTlsaRecords(hostname, port);
            return !records.isEmpty();
        } catch (DnssecValidationException e) {
            LOGGER.warn("TLSA record exists for {}:{} but DNSSEC validation failed: {}",
                hostname, port, e.getMessage());
            return false;
        } catch (Exception e) {
            LOGGER.debug("No TLSA record found for {}:{}: {}", hostname, port, e.getMessage());
            return false;
        }
    }

    @Override
    public List<TlsaExpectation> getTlsaExpectations(String hostname, int port) throws Exception {
        if (policy == DanePolicy.DISABLED) {
            LOGGER.debug("DANE verification disabled, returning empty expectations for {}:{}", hostname, port);
            return List.of();
        }

        LOGGER.debug("Getting TLSA expectations for {}:{} (DNS only, no TLS connection)", hostname, port);

        List<TlsaRecordData> records = queryTlsaRecords(hostname, port);

        // Convert internal TlsaRecordData to public TlsaExpectation
        List<TlsaExpectation> expectations = new java.util.ArrayList<>();
        for (TlsaRecordData record : records) {
            expectations.add(new TlsaExpectation(
                record.selector,
                record.matchingType,
                record.certificateData
            ));
        }

        LOGGER.debug("Found {} TLSA expectation(s) for {}:{}", expectations.size(), hostname, port);
        return expectations;
    }

    /**
     * Queries all TLSA records with DNSSEC validation.
     * Results are cached according to the configured cacheTtl.
     * Dispatches to appropriate method based on validation mode.
     *
     * @return list of TLSA records (may be empty if none found)
     */
    private List<TlsaRecordData> queryTlsaRecords(String hostname, int port) throws Exception {
        // Check cache first
        List<TlsaRecordData> cached = getCachedTlsaRecords(hostname, port);
        if (cached != null) {
            return cached;
        }

        // Cache miss - perform DNS lookup
        List<TlsaRecordData> records = performDnsLookup(hostname, port);

        // Cache the result (including empty results to avoid repeated lookups)
        cacheTlsaRecords(hostname, port, records);

        return records;
    }

    /**
     * Performs the actual DNS lookup for TLSA records.
     * This method is protected to allow overriding in tests.
     *
     * @param hostname the hostname to look up
     * @param port the port number
     * @return list of TLSA records (may be empty if none found)
     * @throws Exception if the DNS lookup fails
     */
    protected List<TlsaRecordData> performDnsLookup(String hostname, int port) throws Exception {
        if (validationMode == DnssecValidationMode.VALIDATE_IN_CODE) {
            return queryTlsaRecordsValidating(hostname, port);
        } else {
            return queryTlsaRecordsTrustResolver(hostname, port);
        }
    }

    /**
     * Queries all TLSA records trusting the upstream resolver's DNSSEC validation (AD flag).
     *
     * @return list of TLSA records (empty if none found)
     */
    private List<TlsaRecordData> queryTlsaRecordsTrustResolver(String hostname, int port) throws Exception {
        String tlsaName = String.format("_%d._tcp.%s", port, hostname);
        LOGGER.debug("Querying DNS for TLSA: {} (trusting resolver AD flag)", tlsaName);

        // Create resolver with DNSSEC support
        SimpleResolver resolver = createSimpleResolver();

        // Build query with DO flag (DNSSEC OK) to request DNSSEC validation
        Name name = Name.fromString(tlsaName + ".");
        Record question = Record.newRecord(name, Type.TLSA, DClass.IN);
        Message query = Message.newQuery(question);

        // Send query and get response
        Message response = resolver.send(query);

        // Check response is valid
        if (response == null) {
            LOGGER.warn("DNS query for {} returned null response", tlsaName);
            return List.of();
        }

        if (response.getHeader() == null) {
            LOGGER.warn("DNS response for {} has null header", tlsaName);
            return List.of();
        }

        // Check for DNSSEC validation (AD flag)
        boolean authenticated = response.getHeader().getFlag(Flags.AD);
        if (!authenticated) {
            LOGGER.warn("TLSA record for {} is NOT DNSSEC-validated (AD flag not set). " +
                "This could indicate: (1) domain doesn't have DNSSEC, " +
                "(2) resolver doesn't support DNSSEC, or (3) validation failed.", tlsaName);
            throw new DnssecValidationException(
                "TLSA record is not DNSSEC-validated. DANE requires DNSSEC for security.");
        }

        LOGGER.debug("DNSSEC validation successful (AD flag set) for {}", tlsaName);

        return extractAllTlsaFromResponse(response, tlsaName);
    }

    /**
     * Queries all TLSA records with in-code DNSSEC validation using ValidatingResolver.
     *
     * <p>This method performs local DNSSEC validation by fetching DNSKEY and RRSIG records
     * and verifying the signature chain. It works with any resolver, including non-DNSSEC ones.</p>
     *
     * @return list of TLSA records (empty if none found)
     */
    private List<TlsaRecordData> queryTlsaRecordsValidating(String hostname, int port) throws Exception {
        String tlsaName = String.format("_%d._tcp.%s", port, hostname);
        LOGGER.debug("Querying DNS for TLSA: {} (in-code DNSSEC validation)", tlsaName);

        // Create ValidatingResolver with base SimpleResolver
        SimpleResolver baseResolver = createSimpleResolver();
        ValidatingResolver validatingResolver = new ValidatingResolver(baseResolver);

        // Use LookupSession for proper CNAME/DNAME handling (as recommended by dnsjava)
        LookupSession session = LookupSession.builder()
            .resolver(validatingResolver)
            .build();

        Name name = Name.fromString(tlsaName + ".");

        try {
            // Perform async lookup and wait for result
            LookupResult result = session.lookupAsync(name, Type.TLSA)
                .toCompletableFuture()
                .get(10, TimeUnit.SECONDS);

            // Check if lookup was successful
            List<Record> records = result.getRecords();
            if (records == null || records.isEmpty()) {
                LOGGER.debug("No TLSA records found for {} (in-code validation)", tlsaName);
                return List.of();
            }

            LOGGER.debug("In-code DNSSEC validation successful for {}", tlsaName);

            // Extract ALL TLSA records
            List<TlsaRecordData> tlsaRecords = new java.util.ArrayList<>();
            for (Record record : records) {
                if (record instanceof TLSARecord tlsaRecord) {
                    int usage = tlsaRecord.getCertificateUsage();
                    int selector = tlsaRecord.getSelector();
                    int matchingType = tlsaRecord.getMatchingType();
                    byte[] certData = tlsaRecord.getCertificateAssociationData();

                    LOGGER.debug("TLSA record (in-code validated): {} {} {} {}",
                        usage, selector, matchingType, TlsaUtils.bytesToHex(certData));

                    tlsaRecords.add(new TlsaRecordData(usage, selector, matchingType, certData));
                }
            }

            LOGGER.debug("Found {} TLSA record(s) for {} (in-code validation)", tlsaRecords.size(), tlsaName);
            return tlsaRecords;

        } catch (java.util.concurrent.ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause != null && cause.getMessage() != null &&
                (cause.getMessage().contains("DNSSEC") ||
                 cause.getMessage().contains("validation") ||
                 cause.getMessage().contains("SERVFAIL"))) {
                LOGGER.warn("In-code DNSSEC validation failed for {}: {}", tlsaName, cause.getMessage());
                throw new DnssecValidationException("DNSSEC validation failed: " + cause.getMessage());
            }
            throw e;
        } catch (java.util.concurrent.TimeoutException e) {
            LOGGER.warn("DNS lookup timed out for {}", tlsaName);
            throw new DnssecValidationException("DNS lookup timed out");
        }
    }

    /**
     * Extracts ALL TLSA records from DNS response.
     *
     * @return list of TLSA records (empty if none found)
     */
    private List<TlsaRecordData> extractAllTlsaFromResponse(Message response, String tlsaName) {
        Record[] answers = response.getSectionArray(Section.ANSWER);
        if (answers == null || answers.length == 0) {
            LOGGER.debug("No TLSA records found for {}", tlsaName);
            return List.of();
        }

        List<TlsaRecordData> tlsaRecords = new java.util.ArrayList<>();
        for (Record record : answers) {
            if (record instanceof TLSARecord tlsaRecord) {
                int usage = tlsaRecord.getCertificateUsage();
                int selector = tlsaRecord.getSelector();
                int matchingType = tlsaRecord.getMatchingType();
                byte[] certData = tlsaRecord.getCertificateAssociationData();

                LOGGER.debug("TLSA record (DNSSEC validated): {} {} {} {}",
                    usage, selector, matchingType, TlsaUtils.bytesToHex(certData));

                tlsaRecords.add(new TlsaRecordData(usage, selector, matchingType, certData));
            }
        }

        LOGGER.debug("Found {} TLSA record(s) for {}", tlsaRecords.size(), tlsaName);
        return tlsaRecords;
    }

    /**
     * Creates and configures a SimpleResolver with DNSSEC support.
     */
    private SimpleResolver createSimpleResolver() throws Exception {
        SimpleResolver resolver;
        if (dnsServer != null && !dnsServer.isBlank()) {
            resolver = resolverFactory.create(dnsServer);
            LOGGER.debug("Using configured DNS server: {}", dnsServer);
        } else {
            if (validationMode == DnssecValidationMode.VALIDATE_IN_CODE) {
                // For in-code validation, system resolver is fine since we validate locally
                resolver = resolverFactory.create(null);
                LOGGER.debug("Using system resolver (in-code DNSSEC validation)");
            } else {
                // For trust-resolver mode, need a DNSSEC-validating resolver
                resolver = resolverFactory.create(DEFAULT_DNSSEC_RESOLVER);
                LOGGER.warn("No DNS server configured. Using external DNSSEC-validating resolver: {}. " +
                    "Configure a custom DNS server to avoid external dependencies.", DEFAULT_DNSSEC_RESOLVER);
            }
        }

        resolver.setTimeout(Duration.ofSeconds(5));

        // Enable EDNS with DO flag for DNSSEC
        resolver.setEDNS(0, 4096, 0x8000, java.util.Collections.emptyList());

        return resolver;
    }

    /**
     * Exception thrown when DNSSEC validation fails.
     */
    public static class DnssecValidationException extends Exception {
        public DnssecValidationException(String message) {
            super(message);
        }
    }

    /**
     * Gets the server's TLS certificate.
     */
    private X509Certificate getServerCertificate(String hostname, int port) throws IOException {
        return certificateFetcher.getCertificate(hostname, port);
    }

    // ==================== Caching Methods ====================

    /**
     * Invalidates the cached TLSA lookup for a specific host and port.
     *
     * @param hostname the hostname
     * @param port the port
     */
    public void invalidate(String hostname, int port) {
        String key = cacheKey(hostname, port);
        tlsaCache.remove(key);
        LOGGER.debug("Invalidated TLSA cache for {}:{}", hostname, port);
    }

    /**
     * Clears all cached TLSA lookup results.
     */
    public void clearCache() {
        tlsaCache.clear();
        LOGGER.debug("Cleared TLSA lookup cache");
    }

    /**
     * Returns the number of cached TLSA lookup entries.
     *
     * @return the cache size
     */
    public int cacheSize() {
        return tlsaCache.size();
    }

    /**
     * Returns the current DANE policy.
     */
    public DanePolicy getPolicy() {
        return policy;
    }

    /**
     * Returns the current DNSSEC validation mode.
     */
    public DnssecValidationMode getValidationMode() {
        return validationMode;
    }

    /**
     * Gets cached TLSA records for a hostname and port.
     *
     * @return the cached records, or null if not cached or expired
     */
    private List<TlsaRecordData> getCachedTlsaRecords(String hostname, int port) {
        if (cacheTtl.isZero()) {
            return null;
        }

        String key = cacheKey(hostname, port);
        CachedTlsaRecords cached = tlsaCache.get(key);

        if (cached != null && !cached.isExpired()) {
            LOGGER.debug("Using cached TLSA records for {}:{} ({} record(s))",
                hostname, port, cached.records.size());
            return cached.records;
        }

        if (cached != null) {
            tlsaCache.remove(key);
            LOGGER.debug("Expired TLSA cache entry removed for {}:{}", hostname, port);
        }

        return null;
    }

    /**
     * Caches TLSA records for a hostname and port.
     *
     * @param hostname the hostname
     * @param port the port
     * @param records the TLSA records to cache (may be empty)
     */
    private void cacheTlsaRecords(String hostname, int port, List<TlsaRecordData> records) {
        if (cacheTtl.isZero()) {
            return;
        }

        String key = cacheKey(hostname, port);
        tlsaCache.put(key, new CachedTlsaRecords(records, cacheTtl));
        LOGGER.debug("Cached {} TLSA record(s) for {}:{} (ttl={})",
            records.size(), hostname, port, cacheTtl);
    }

    private String cacheKey(String hostname, int port) {
        return hostname + ":" + port;
    }

    /**
     * Internal representation of a TLSA record.
     * Package-private to allow testing.
     */
    static class TlsaRecordData {
        final int usage;
        final int selector;
        final int matchingType;
        final byte[] certificateData;

        TlsaRecordData(int usage, int selector, int matchingType, byte[] certificateData) {
            this.usage = usage;
            this.selector = selector;
            this.matchingType = matchingType;
            this.certificateData = certificateData;
        }
    }

    /**
     * Cached TLSA records with expiration.
     */
    private static class CachedTlsaRecords {
        final List<TlsaRecordData> records;
        final Instant expiresAt;

        CachedTlsaRecords(List<TlsaRecordData> records, Duration ttl) {
            this.records = records;
            this.expiresAt = Instant.now().plus(ttl);
        }

        boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }
    }
}
