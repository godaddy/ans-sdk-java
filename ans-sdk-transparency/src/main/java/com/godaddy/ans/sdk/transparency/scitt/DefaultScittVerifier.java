package com.godaddy.ans.sdk.transparency.scitt;

import com.godaddy.ans.sdk.crypto.CertificateUtils;
import com.godaddy.ans.sdk.crypto.CryptoCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Default implementation of {@link ScittVerifier}.
 *
 * <p>This implementation performs:</p>
 * <ul>
 *   <li>COSE_Sign1 signature verification using ES256</li>
 *   <li>RFC 9162 Merkle inclusion proof verification</li>
 *   <li>Status token expiry checking with clock skew tolerance</li>
 *   <li>Constant-time fingerprint comparison</li>
 * </ul>
 */
public final class DefaultScittVerifier implements ScittVerifier {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultScittVerifier.class);

    private final Duration clockSkewTolerance;
    private final String expectedIssuer;

    /**
     * Creates a new verifier with default clock skew tolerance (60 seconds).
     *
     * @param expectedIssuer the expected issuer domain (C2SP domain of the transparency log)
     */
    public DefaultScittVerifier(String expectedIssuer) {
        this(StatusToken.DEFAULT_CLOCK_SKEW, expectedIssuer);
    }

    /**
     * Creates a new verifier with the specified clock skew tolerance.
     *
     * @param clockSkewTolerance the clock skew tolerance for token expiry checks
     * @param expectedIssuer the expected issuer domain (C2SP domain of the transparency log)
     */
    public DefaultScittVerifier(Duration clockSkewTolerance, String expectedIssuer) {
        this.clockSkewTolerance = Objects.requireNonNull(clockSkewTolerance, "clockSkewTolerance cannot be null");
        this.expectedIssuer = Objects.requireNonNull(expectedIssuer, "expectedIssuer cannot be null");
    }

    @Override
    public ScittExpectation verify(
            ScittReceipt receipt,
            StatusToken token,
            Map<String, PublicKey> rootKeys) {

        Objects.requireNonNull(receipt, "receipt cannot be null");
        Objects.requireNonNull(token, "token cannot be null");
        Objects.requireNonNull(rootKeys, "rootKeys cannot be null");

        if (rootKeys.isEmpty()) {
            return ScittExpectation.invalidReceipt("No root keys available for verification");
        }

        LOGGER.debug("Verifying SCITT artifacts for agent {} (have {} root keys)",
            token.agentId(), rootKeys.size());

        try {
            // 1. Look up receipt key by key ID (O(1) map lookup)
            String receiptKeyId = receipt.protectedHeader().keyIdHex();
            PublicKey receiptKey = rootKeys.get(receiptKeyId);
            if (receiptKey == null) {
                LOGGER.warn("Receipt key ID {} not in trust store (have {} keys)",
                    receiptKeyId, rootKeys.size());
                return ScittExpectation.keyNotFound(
                    "Receipt key ID " + receiptKeyId + " not in trust store (have " + rootKeys.size() + " keys)");
            }
            LOGGER.debug("Found receipt key with ID {}", receiptKeyId);

            // 2. Verify receipt signature
            if (!verifyReceiptSignature(receipt, receiptKey)) {
                LOGGER.warn("Receipt signature verification failed for agent {}", token.agentId());
                return ScittExpectation.invalidReceipt("Receipt signature verification failed");
            }
            LOGGER.debug("Receipt signature verified for agent {}", token.agentId());

            // 2a. Validate receipt issuer binding
            String issuerError = validateIssuer(receipt.protectedHeader(), "Receipt");
            if (issuerError != null) {
                return ScittExpectation.invalidReceipt(issuerError);
            }

            // 3. Verify Merkle inclusion proof
            if (!verifyMerkleProof(receipt)) {
                LOGGER.warn("Merkle proof verification failed for agent {}", token.agentId());
                return ScittExpectation.invalidReceipt("Merkle proof verification failed");
            }
            LOGGER.debug("Merkle proof verified for agent {}", token.agentId());

            // 4. Look up token key by key ID (O(1) map lookup)
            String tokenKeyId = token.protectedHeader().keyIdHex();
            PublicKey tokenKey = rootKeys.get(tokenKeyId);
            if (tokenKey == null) {
                LOGGER.warn("Token key ID {} not in trust store (have {} keys)",
                    tokenKeyId, rootKeys.size());
                return ScittExpectation.keyNotFound(
                    "Token key ID " + tokenKeyId + " not in trust store (have " + rootKeys.size() + " keys)");
            }
            LOGGER.debug("Found token key with ID {}", tokenKeyId);

            // 5. Verify status token signature
            if (!verifyTokenSignature(token, tokenKey)) {
                LOGGER.warn("Status token signature verification failed for agent {}", token.agentId());
                return ScittExpectation.invalidToken("Status token signature verification failed");
            }
            LOGGER.debug("Status token signature verified for agent {}", token.agentId());

            // 5a. Validate token issuer binding
            issuerError = validateIssuer(token.protectedHeader(), "Status token");
            if (issuerError != null) {
                return ScittExpectation.invalidToken(issuerError);
            }

            // 6. Check status token expiry
            Instant now = Instant.now();
            if (token.isExpired(now, clockSkewTolerance)) {
                LOGGER.warn("Status token expired for agent {} (expired at {})",
                    token.agentId(), token.expiresAt());
                return ScittExpectation.expired();
            }

            // 7. Check agent status
            if (token.status() == StatusToken.Status.REVOKED) {
                LOGGER.warn("Agent {} is revoked", token.agentId());
                return ScittExpectation.revoked(token.ansName());
            }

            if (token.status() != StatusToken.Status.ACTIVE &&
                token.status() != StatusToken.Status.WARNING) {
                LOGGER.warn("Agent {} has status {}", token.agentId(), token.status());
                return ScittExpectation.inactive(token.status(), token.ansName());
            }

            // 8. Extract expectations
            LOGGER.debug("SCITT verification successful for agent {}", token.agentId());
            return ScittExpectation.verified(
                token.serverCertFingerprints(),
                token.identityCertFingerprints(),
                    token.ansName(),
                token.metadataHashes(),
                token
            );

        } catch (Exception e) {
            LOGGER.error("SCITT verification error for agent {}: {}", token.agentId(), e.getMessage());
            return ScittExpectation.parseError("Verification error: " + e.getMessage());
        }
    }

    @Override
    public ScittVerificationResult postVerify(
            String hostname,
            X509Certificate serverCert,
            ScittExpectation expectation) {

        Objects.requireNonNull(hostname, "hostname cannot be null");
        Objects.requireNonNull(serverCert, "serverCert cannot be null");
        Objects.requireNonNull(expectation, "expectation cannot be null");

        // If expectation indicates failure, return error
        if (!expectation.isVerified()) {
            return ScittVerificationResult.error(
                "SCITT pre-verification failed: " + expectation.failureReason());
        }

        List<String> expectedFingerprints = expectation.validServerCertFingerprints();
        if (expectedFingerprints.isEmpty()) {
            return ScittVerificationResult.error("No server certificate fingerprints in expectation");
        }

        try {
            // Compute actual fingerprint
            String actualFingerprint = computeCertificateFingerprint(serverCert);

            LOGGER.debug("Comparing certificate fingerprint {} against {} expected fingerprints",
                CertificateUtils.truncateFingerprint(actualFingerprint), expectedFingerprints.size());

            // SECURITY: Use constant-time comparison for fingerprints
            for (String expectedFingerprint : expectedFingerprints) {
                if (CertificateUtils.fingerprintMatches(actualFingerprint, expectedFingerprint)) {
                    LOGGER.debug("Certificate fingerprint matches for {}", hostname);
                    return ScittVerificationResult.success(actualFingerprint);
                }
            }

            // No match found
            LOGGER.warn("Certificate fingerprint mismatch for {}: got {}, expected one of {}",
                hostname, CertificateUtils.truncateFingerprint(actualFingerprint), expectedFingerprints.size());
            return ScittVerificationResult.mismatch(
                actualFingerprint,
                "Certificate fingerprint does not match any expected fingerprint");

        } catch (Exception e) {
            LOGGER.error("Error computing certificate fingerprint: {}", e.getMessage());
            return ScittVerificationResult.error("Error computing fingerprint: " + e.getMessage());
        }
    }

    /**
     * Validates the issuer (iss) CWT claim against the expected transparency log domain.
     *
     * @param header the COSE protected header containing CWT claims
     * @param artifactType description for logging (e.g., "Receipt", "Status token")
     * @return error message if validation fails, null if valid
     */
    private String validateIssuer(CoseProtectedHeader header, String artifactType) {
        if (header == null || header.cwtClaims() == null) {
            LOGGER.warn("{} missing CWT claims — cannot validate issuer", artifactType);
            return artifactType + " missing CWT claims (expected issuer '" + expectedIssuer + "')";
        }
        String iss = header.cwtClaims().iss();
        if (iss == null) {
            LOGGER.warn("{} missing issuer claim — expected '{}'", artifactType, expectedIssuer);
            return artifactType + " missing issuer claim (expected '" + expectedIssuer + "')";
        }
        if (!expectedIssuer.equals(iss)) {
            LOGGER.warn("{} issuer mismatch: expected '{}', got '{}'",
                artifactType, expectedIssuer, iss);
            return artifactType + " issuer mismatch: expected '" + expectedIssuer
                + "', got '" + iss + "'";
        }
        return null;
    }

    /**
     * Verifies the receipt's COSE_Sign1 signature using the TL public key.
     *
     * <p>Note: Key ID validation is performed before this method is called
     * via the rootKeys map lookup.</p>
     */
    private boolean verifyReceiptSignature(ScittReceipt receipt, PublicKey tlPublicKey) {
        try {
            // Build Sig_structure for verification
            byte[] sigStructure = CoseSign1Parser.buildSigStructure(
                receipt.protectedHeaderBytes(),
                null,  // No external AAD
                receipt.eventPayload()
            );

            // Verify ES256 signature
            return verifyEs256Signature(sigStructure, receipt.signature(), tlPublicKey);

        } catch (Exception e) {
            LOGGER.error("Receipt signature verification error: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Verifies the Merkle inclusion proof in the receipt.
     */
    private boolean verifyMerkleProof(ScittReceipt receipt) {
        try {
            ScittReceipt.InclusionProof proof = receipt.inclusionProof();

            if (proof == null) {
                LOGGER.error("Receipt missing inclusion proof");
                return false;
            }

            // If we have all the components, verify the proof
            if (proof.treeSize() > 0 && proof.rootHash() != null && receipt.eventPayload() != null) {
                return MerkleProofVerifier.verifyInclusion(
                    receipt.eventPayload(),
                    proof.leafIndex(),
                    proof.treeSize(),
                    proof.hashPath(),
                    proof.rootHash()
                );
            }

            // Incomplete Merkle proof data - fail verification
            // All components are required to prove the entry exists in the append-only log
            LOGGER.error("Incomplete Merkle proof data (treeSize={}, hasRootHash={}, hasPayload={}), " +
                "cannot verify log inclusion",
                proof.treeSize(),
                proof.rootHash() != null,
                receipt.eventPayload() != null);
            return false;

        } catch (Exception e) {
            LOGGER.error("Merkle proof verification error: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Verifies the status token's COSE_Sign1 signature using the RA public key.
     *
     * <p>Note: Key ID validation is performed before this method is called
     * via the rootKeys map lookup.</p>
     */
    private boolean verifyTokenSignature(StatusToken token, PublicKey raPublicKey) {
        try {
            // Build Sig_structure for verification
            byte[] sigStructure = CoseSign1Parser.buildSigStructure(
                token.protectedHeaderBytes(),
                null,  // No external AAD
                token.payload()
            );

            // Verify ES256 signature
            return verifyEs256Signature(sigStructure, token.signature(), raPublicKey);

        } catch (Exception e) {
            LOGGER.error("Token signature verification error: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Verifies an ES256 (ECDSA with SHA-256 on P-256) signature.
     *
     * @param data the data that was signed
     * @param signature the signature in IEEE P1363 format (64 bytes: r || s)
     * @param publicKey the EC public key
     * @return true if signature is valid
     */
    private boolean verifyEs256Signature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        return CryptoCache.verifyEs256P1363(data, signature, publicKey);
    }

    /**
     * Computes the SHA-256 fingerprint of an X.509 certificate.
     */
    private String computeCertificateFingerprint(X509Certificate cert) throws Exception {
        return CertificateUtils.bytesToHex(CryptoCache.sha256(cert.getEncoded()));
    }
}
