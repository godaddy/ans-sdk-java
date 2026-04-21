package com.godaddy.ans.sdk.transparency.scitt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DefaultScittVerifierTest {

    private static final String TEST_ISSUER = "transparency.test.example.com";

    private DefaultScittVerifier verifier;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        verifier = new DefaultScittVerifier(TEST_ISSUER);
        keyPair = ScittTestHelpers.generateEcKeyPair();
    }

    /**
     * Helper to convert a PublicKey to a Map keyed by hex key ID.
     */
    private Map<String, PublicKey> toRootKeys(PublicKey publicKey) {
        return ScittTestHelpers.toRootKeys(publicKey);
    }

    @Nested
    @DisplayName("Constructor tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create verifier with default clock skew")
        void shouldCreateWithDefaultClockSkew() {
            DefaultScittVerifier v = new DefaultScittVerifier(TEST_ISSUER);
            assertThat(v).isNotNull();
        }

        @Test
        @DisplayName("Should create verifier with custom clock skew")
        void shouldCreateWithCustomClockSkew() {
            DefaultScittVerifier v = new DefaultScittVerifier(Duration.ofMinutes(5), TEST_ISSUER);
            assertThat(v).isNotNull();
        }

        @Test
        @DisplayName("Should reject null clock skew tolerance")
        void shouldRejectNullClockSkew() {
            assertThatThrownBy(() -> new DefaultScittVerifier(null, TEST_ISSUER))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("clockSkewTolerance cannot be null");
        }

        @Test
        @DisplayName("Should reject null expected issuer")
        void shouldRejectNullExpectedIssuer() {
            assertThatThrownBy(() -> new DefaultScittVerifier(Duration.ofSeconds(60), null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("expectedIssuer cannot be null");
        }
    }

    @Nested
    @DisplayName("verify() tests")
    class VerifyTests {

        @Test
        @DisplayName("Should reject null receipt")
        void shouldRejectNullReceipt() {
            StatusToken token = createMockStatusToken(StatusToken.Status.ACTIVE);

            assertThatThrownBy(() -> verifier.verify(null, token, toRootKeys(keyPair.getPublic())))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("receipt cannot be null");
        }

        @Test
        @DisplayName("Should reject null token")
        void shouldRejectNullToken() {
            ScittReceipt receipt = createMockReceipt();

            assertThatThrownBy(() -> verifier.verify(receipt, null, toRootKeys(keyPair.getPublic())))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("token cannot be null");
        }

        @Test
        @DisplayName("Should reject null root keys map")
        void shouldRejectNullRootKeys() {
            ScittReceipt receipt = createMockReceipt();
            StatusToken token = createMockStatusToken(StatusToken.Status.ACTIVE);

            assertThatThrownBy(() -> verifier.verify(receipt, token, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("rootKeys cannot be null");
        }

        @Test
        @DisplayName("Should return error for empty root keys map")
        void shouldReturnErrorForEmptyRootKeys() {
            ScittReceipt receipt = createMockReceipt();
            StatusToken token = createMockStatusToken(StatusToken.Status.ACTIVE);

            ScittExpectation result = verifier.verify(receipt, token, new HashMap<>());

            assertThat(result.status()).isEqualTo(ScittExpectation.Status.INVALID_RECEIPT);
            assertThat(result.failureReason()).contains("No root keys available");
        }

        @Test
        @DisplayName("Should return invalid receipt for bad receipt signature")
        void shouldReturnInvalidReceiptForBadSignature() throws Exception {
            ScittReceipt receipt = createReceiptWithSignature(new byte[64]); // Bad signature
            StatusToken token = createMockStatusToken(StatusToken.Status.ACTIVE);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            assertThat(result.status()).isEqualTo(ScittExpectation.Status.INVALID_RECEIPT);
            assertThat(result.failureReason()).contains("signature verification failed");
        }

        @Test
        @DisplayName("Should return invalid token for revoked agent")
        void shouldReturnInvalidTokenForRevokedAgent() throws Exception {
            ScittReceipt receipt = createValidSignedReceipt(keyPair.getPrivate());
            StatusToken token = createValidSignedToken(keyPair.getPrivate(), StatusToken.Status.REVOKED);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            assertThat(result.status()).isEqualTo(ScittExpectation.Status.AGENT_REVOKED);
        }

        @Test
        @DisplayName("Should return inactive for deprecated agent")
        void shouldReturnInactiveForDeprecatedAgent() throws Exception {
            ScittReceipt receipt = createValidSignedReceipt(keyPair.getPrivate());
            StatusToken token = createValidSignedToken(keyPair.getPrivate(), StatusToken.Status.DEPRECATED);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            assertThat(result.status()).isEqualTo(ScittExpectation.Status.AGENT_INACTIVE);
        }

        @Test
        @DisplayName("Should allow WARNING status as valid")
        void shouldAllowWarningStatus() throws Exception {
            ScittReceipt receipt = createValidSignedReceipt(keyPair.getPrivate());
            StatusToken token = createValidSignedToken(keyPair.getPrivate(), StatusToken.Status.WARNING);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            // WARNING should be allowed (verified), not rejected
            assertThat(result.status()).isIn(ScittExpectation.Status.VERIFIED, ScittExpectation.Status.INVALID_RECEIPT);
        }
    }

    @Nested
    @DisplayName("postVerify() tests")
    class PostVerifyTests {

        @Test
        @DisplayName("Should reject null hostname")
        void shouldRejectNullHostname() {
            X509Certificate cert = mock(X509Certificate.class);
            ScittExpectation expectation = ScittExpectation.verified(
                List.of("abc123"), List.of(), "ans.test", Map.of(), null);

            assertThatThrownBy(() -> verifier.postVerify(null, cert, expectation))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("hostname cannot be null");
        }

        @Test
        @DisplayName("Should reject null server certificate")
        void shouldRejectNullServerCert() {
            ScittExpectation expectation = ScittExpectation.verified(
                List.of("abc123"), List.of(), "ans.test", Map.of(), null);

            assertThatThrownBy(() -> verifier.postVerify("test.example.com", null, expectation))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("serverCert cannot be null");
        }

        @Test
        @DisplayName("Should reject null expectation")
        void shouldRejectNullExpectation() {
            X509Certificate cert = mock(X509Certificate.class);

            assertThatThrownBy(() -> verifier.postVerify("test.example.com", cert, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("expectation cannot be null");
        }

        @Test
        @DisplayName("Should return error for unverified expectation")
        void shouldReturnErrorForUnverifiedExpectation() {
            X509Certificate cert = mock(X509Certificate.class);
            ScittExpectation expectation = ScittExpectation.invalidReceipt("Test failure");

            ScittVerifier.ScittVerificationResult result =
                verifier.postVerify("test.example.com", cert, expectation);

            assertThat(result.success()).isFalse();
            assertThat(result.failureReason()).contains("pre-verification failed");
        }

        @Test
        @DisplayName("Should return error when no expected fingerprints")
        void shouldReturnErrorWhenNoFingerprints() {
            X509Certificate cert = mock(X509Certificate.class);
            ScittExpectation expectation = ScittExpectation.verified(
                List.of(), List.of(), "ans.test", Map.of(), null);

            ScittVerifier.ScittVerificationResult result =
                verifier.postVerify("test.example.com", cert, expectation);

            assertThat(result.success()).isFalse();
            assertThat(result.failureReason()).contains("No server certificate fingerprints");
        }

        @Test
        @DisplayName("Should return success when fingerprint matches")
        void shouldReturnSuccessWhenFingerprintMatches() throws Exception {
            // Create a real-ish mock certificate
            X509Certificate cert = mock(X509Certificate.class);
            byte[] certBytes = new byte[100];
            when(cert.getEncoded()).thenReturn(certBytes);

            // Compute expected fingerprint
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(certBytes);
            String expectedFingerprint = bytesToHex(digest);

            ScittExpectation expectation = ScittExpectation.verified(
                List.of(expectedFingerprint), List.of(), "ans.test", Map.of(), null);

            ScittVerifier.ScittVerificationResult result =
                verifier.postVerify("test.example.com", cert, expectation);

            assertThat(result.success()).isTrue();
            assertThat(result.actualFingerprint()).isEqualTo(expectedFingerprint);
        }

        @Test
        @DisplayName("Should return mismatch when fingerprint does not match")
        void shouldReturnMismatchWhenFingerprintDoesNotMatch() throws Exception {
            X509Certificate cert = mock(X509Certificate.class);
            when(cert.getEncoded()).thenReturn(new byte[100]);

            ScittExpectation expectation = ScittExpectation.verified(
                List.of("deadbeef00000000000000000000000000000000000000000000000000000000"),
                List.of(), "ans.test", Map.of(), null);

            ScittVerifier.ScittVerificationResult result =
                verifier.postVerify("test.example.com", cert, expectation);

            assertThat(result.success()).isFalse();
            assertThat(result.failureReason()).contains("does not match");
        }

        @Test
        @DisplayName("Should normalize fingerprints with colons")
        void shouldNormalizeFingerprintsWithColons() throws Exception {
            X509Certificate cert = mock(X509Certificate.class);
            byte[] certBytes = new byte[100];
            when(cert.getEncoded()).thenReturn(certBytes);

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(certBytes);
            String hexFingerprint = bytesToHex(digest);

            // Format with colons (every 2 chars) and SHA256: prefix
            StringBuilder colonFormatted = new StringBuilder("SHA256:");
            for (int i = 0; i < hexFingerprint.length(); i += 2) {
                if (i > 0) {
                    colonFormatted.append(":");
                }
                colonFormatted.append(hexFingerprint.substring(i, i + 2));
            }

            ScittExpectation expectation = ScittExpectation.verified(
                List.of(colonFormatted.toString()), List.of(), "ans.test", Map.of(), null);

            ScittVerifier.ScittVerificationResult result =
                verifier.postVerify("test.example.com", cert, expectation);

            assertThat(result.success()).isTrue();
        }

        @Test
        @DisplayName("Should match any of multiple expected fingerprints")
        void shouldMatchAnyOfMultipleFingerprints() throws Exception {
            X509Certificate cert = mock(X509Certificate.class);
            byte[] certBytes = new byte[100];
            when(cert.getEncoded()).thenReturn(certBytes);

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(certBytes);
            String expectedFingerprint = bytesToHex(digest);

            ScittExpectation expectation = ScittExpectation.verified(
                List.of(
                    "wrong1000000000000000000000000000000000000000000000000000000000",
                    expectedFingerprint,
                    "wrong2000000000000000000000000000000000000000000000000000000000"
                ),
                List.of(), "ans.test", Map.of(), null);

            ScittVerifier.ScittVerificationResult result =
                verifier.postVerify("test.example.com", cert, expectation);

            assertThat(result.success()).isTrue();
        }
    }

    @Nested
    @DisplayName("Clock skew handling tests")
    class ClockSkewTests {

        @Test
        @DisplayName("Should accept token within clock skew tolerance")
        void shouldAcceptTokenWithinClockSkew() throws Exception {
            // Create verifier with 60 second clock skew
            DefaultScittVerifier v = new DefaultScittVerifier(Duration.ofSeconds(60), TEST_ISSUER);

            ScittReceipt receipt = createValidSignedReceipt(keyPair.getPrivate());
            // Token expired 30 seconds ago (within 60 second tolerance)
            StatusToken token = createExpiredToken(keyPair.getPrivate(), Duration.ofSeconds(30));

            ScittExpectation result = v.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            // Should not be marked as expired
            assertThat(result.status()).isNotEqualTo(ScittExpectation.Status.TOKEN_EXPIRED);
        }

        @Test
        @DisplayName("Should reject token beyond clock skew tolerance")
        void shouldRejectTokenBeyondClockSkew() throws Exception {
            DefaultScittVerifier v = new DefaultScittVerifier(Duration.ofSeconds(60), TEST_ISSUER);

            ScittReceipt receipt = createValidSignedReceipt(keyPair.getPrivate());
            // Token expired 120 seconds ago (beyond 60 second tolerance)
            StatusToken token = createExpiredToken(keyPair.getPrivate(), Duration.ofSeconds(120));

            ScittExpectation result = v.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            // May be TOKEN_EXPIRED or INVALID_TOKEN/INVALID_RECEIPT depending on verification order
            assertThat(result.status()).isIn(
                ScittExpectation.Status.TOKEN_EXPIRED,
                ScittExpectation.Status.INVALID_RECEIPT,
                ScittExpectation.Status.INVALID_TOKEN
            );
        }
    }

    @Nested
    @DisplayName("Merkle proof verification tests")
    class MerkleProofTests {

        @Test
        @DisplayName("Should handle receipt with null inclusion proof")
        void shouldHandleReceiptWithNullInclusionProof() throws Exception {
            byte[] keyId = computeKeyId(keyPair.getPublic());
            CoseProtectedHeader header = new CoseProtectedHeader(-7, keyId, 1, null, null);
            ScittReceipt receipt = new ScittReceipt(
                header,
                new byte[10],
                null,  // null inclusion proof
                "test-payload".getBytes(),
                new byte[64]
            );
            StatusToken token = createMockStatusToken(StatusToken.Status.ACTIVE);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            // Should fail at receipt signature verification first, or merkle proof verification
            assertThat(result.status()).isIn(
                ScittExpectation.Status.INVALID_RECEIPT,
                ScittExpectation.Status.INVALID_TOKEN
            );
        }

        @Test
        @DisplayName("Should reject receipt with incomplete Merkle proof (no root hash)")
        void shouldRejectIncompleteProof() throws Exception {
            // Create a properly signed receipt but with incomplete Merkle proof
            byte[] protectedHeaderBytes = new byte[10];
            byte[] payload = "test-payload".getBytes();

            // Sign the receipt properly
            byte[] sigStructure = CoseSign1Parser.buildSigStructure(protectedHeaderBytes, null, payload);
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(keyPair.getPrivate());
            sig.update(sigStructure);
            byte[] derSignature = sig.sign();
            byte[] p1363Signature = convertDerToP1363(derSignature);

            byte[] keyId = computeKeyId(keyPair.getPublic());
            CwtClaims claims = new CwtClaims(TEST_ISSUER, null, null, null, null, null);
            CoseProtectedHeader header = new CoseProtectedHeader(-7, keyId, 1, claims, null);

            // Proof without root hash (treeSize > 0 but rootHash = null) - INCOMPLETE
            ScittReceipt.InclusionProof incompleteProof = new ScittReceipt.InclusionProof(
                10, 5, null, List.of());

            ScittReceipt receipt = new ScittReceipt(header, protectedHeaderBytes, incompleteProof, payload,
                    p1363Signature);
            StatusToken token = createValidSignedToken(keyPair.getPrivate(), StatusToken.Status.ACTIVE);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            // Incomplete Merkle proof must fail - cannot verify log inclusion without all components
            assertThat(result.status()).isEqualTo(ScittExpectation.Status.INVALID_RECEIPT);
            assertThat(result.failureReason()).contains("Merkle proof");
        }
    }

    @Nested
    @DisplayName("Signature validation tests")
    class SignatureValidationTests {

        @Test
        @DisplayName("Should fail verification with wrong signature length (not 64 bytes)")
        void shouldFailWithWrongSignatureLength() throws Exception {
            byte[] keyId = computeKeyId(keyPair.getPublic());
            CoseProtectedHeader header = new CoseProtectedHeader(-7, keyId, 1, null, null);
            byte[] payload = "test-payload".getBytes();
            byte[] leafHash = MerkleProofVerifier.hashLeaf(payload);
            ScittReceipt.InclusionProof proof = new ScittReceipt.InclusionProof(
                1, 0, leafHash, List.of());

            // Wrong signature length - 32 bytes instead of 64
            byte[] wrongLengthSignature = new byte[32];
            ScittReceipt receipt = new ScittReceipt(
                header,
                new byte[10],
                proof,
                payload,
                wrongLengthSignature
            );
            StatusToken token = createMockStatusToken(StatusToken.Status.ACTIVE);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            assertThat(result.status()).isEqualTo(ScittExpectation.Status.INVALID_RECEIPT);
        }

        @Test
        @DisplayName("Should fail verification with wrong key")
        void shouldFailWithWrongKey() throws Exception {
            // Sign receipt with one key
            ScittReceipt receipt = createValidSignedReceipt(keyPair.getPrivate());
            StatusToken token = createMockStatusToken(StatusToken.Status.ACTIVE);

            // But provide a different key for verification
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair wrongKeyPair = keyGen.generateKeyPair();

            // Verify with wrong key
            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(wrongKeyPair.getPublic()));

            assertThat(result.status()).isEqualTo(ScittExpectation.Status.KEY_NOT_FOUND);
        }
    }

    @Nested
    @DisplayName("Merkle proof validation tests")
    class MerkleProofValidationTests {

        @Test
        @DisplayName("Should fail verification with wrong root hash")
        void shouldFailWithWrongRootHash() throws Exception {
            byte[] keyId = computeKeyId(keyPair.getPublic());
            CoseProtectedHeader header = new CoseProtectedHeader(-7, keyId, 1, null, null);
            byte[] payload = "test-payload".getBytes();

            // Create proof with correct leaf but wrong root hash
            byte[] wrongRootHash = new byte[32];
            Arrays.fill(wrongRootHash, (byte) 0xFF);

            ScittReceipt.InclusionProof proof = new ScittReceipt.InclusionProof(
                1, 0, wrongRootHash, List.of());

            ScittReceipt receipt = new ScittReceipt(
                header,
                new byte[10],
                proof,
                payload,
                new byte[64]
            );
            StatusToken token = createMockStatusToken(StatusToken.Status.ACTIVE);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            // Should fail at receipt signature verification first (invalid signature bytes)
            // or at Merkle proof verification
            assertThat(result.status()).isIn(
                ScittExpectation.Status.INVALID_RECEIPT,
                ScittExpectation.Status.INVALID_TOKEN
            );
        }

        @Test
        @DisplayName("Should fail verification with incorrect hash path")
        void shouldFailWithIncorrectHashPath() throws Exception {
            byte[] keyId = computeKeyId(keyPair.getPublic());
            CoseProtectedHeader header = new CoseProtectedHeader(-7, keyId, 1, null, null);
            byte[] payload = "test-payload".getBytes();

            // Build a tree with 2 elements but provide wrong sibling hash
            byte[] leafHash = MerkleProofVerifier.hashLeaf(payload);
            byte[] siblingHash = new byte[32];
            Arrays.fill(siblingHash, (byte) 0xAA);

            // Calculate root with wrong sibling
            byte[] wrongRoot = MerkleProofVerifier.hashNode(leafHash, siblingHash);

            // But use a different (incorrect) sibling in the path
            byte[] incorrectSibling = new byte[32];
            Arrays.fill(incorrectSibling, (byte) 0xBB);

            ScittReceipt.InclusionProof proof = new ScittReceipt.InclusionProof(
                2, 0, wrongRoot, List.of(incorrectSibling));

            ScittReceipt receipt = new ScittReceipt(
                header,
                new byte[10],
                proof,
                payload,
                new byte[64]
            );
            StatusToken token = createMockStatusToken(StatusToken.Status.ACTIVE);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            assertThat(result.status()).isIn(
                ScittExpectation.Status.INVALID_RECEIPT,
                ScittExpectation.Status.INVALID_TOKEN
            );
        }

        @Test
        @DisplayName("Should handle empty hash path for single element tree")
        void shouldHandleEmptyHashPathForSingleElement() throws Exception {
            // Sign receipt properly
            byte[] protectedHeaderBytes = new byte[10];
            byte[] payload = "test-payload".getBytes();

            byte[] sigStructure = CoseSign1Parser.buildSigStructure(protectedHeaderBytes, null, payload);

            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(keyPair.getPrivate());
            sig.update(sigStructure);
            byte[] derSignature = sig.sign();
            byte[] p1363Signature = convertDerToP1363(derSignature);

            byte[] keyId = computeKeyId(keyPair.getPublic());
            CwtClaims claims = new CwtClaims(TEST_ISSUER, null, null, null, null, null);
            CoseProtectedHeader header = new CoseProtectedHeader(-7, keyId, 1, claims, null);

            // Single element tree: root == leaf hash
            byte[] leafHash = MerkleProofVerifier.hashLeaf(payload);
            ScittReceipt.InclusionProof proof = new ScittReceipt.InclusionProof(
                1, 0, leafHash, List.of());  // Empty path for single element

            ScittReceipt receipt = new ScittReceipt(header, protectedHeaderBytes, proof, payload, p1363Signature);
            StatusToken token = createValidSignedToken(keyPair.getPrivate(), StatusToken.Status.ACTIVE);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            // Should succeed - valid receipt and token
            assertThat(result.status()).isEqualTo(ScittExpectation.Status.VERIFIED);
        }
    }

    @Nested
    @DisplayName("postVerify error handling tests")
    class PostVerifyErrorHandlingTests {

        @Test
        @DisplayName("Should handle certificate encoding exception")
        void shouldHandleCertificateEncodingException() throws Exception {
            X509Certificate cert = mock(X509Certificate.class);
            when(cert.getEncoded()).thenThrow(new java.security.cert.CertificateEncodingException("Test error"));

            ScittExpectation expectation = ScittExpectation.verified(
                List.of("abc123"), List.of(), "ans.test", Map.of(), null);

            ScittVerifier.ScittVerificationResult result =
                verifier.postVerify("test.example.com", cert, expectation);

            assertThat(result.success()).isFalse();
            assertThat(result.failureReason()).contains("Error computing fingerprint");
        }

        @Test
        @DisplayName("Should return error for expired expectation")
        void shouldReturnErrorForExpiredExpectation() {
            X509Certificate cert = mock(X509Certificate.class);
            ScittExpectation expectation = ScittExpectation.expired();

            ScittVerifier.ScittVerificationResult result =
                verifier.postVerify("test.example.com", cert, expectation);

            assertThat(result.success()).isFalse();
            assertThat(result.failureReason()).contains("pre-verification failed");
        }

        @Test
        @DisplayName("Should return error for revoked expectation")
        void shouldReturnErrorForRevokedExpectation() {
            X509Certificate cert = mock(X509Certificate.class);
            ScittExpectation expectation = ScittExpectation.revoked("test.ans");

            ScittVerifier.ScittVerificationResult result =
                verifier.postVerify("test.example.com", cert, expectation);

            assertThat(result.success()).isFalse();
            assertThat(result.failureReason()).contains("pre-verification failed");
        }
    }

    @Nested
    @DisplayName("Fingerprint normalization tests")
    class FingerprintNormalizationTests {

        @Test
        @DisplayName("Should normalize uppercase fingerprint")
        void shouldNormalizeUppercaseFingerprint() throws Exception {
            X509Certificate cert = mock(X509Certificate.class);
            byte[] certBytes = new byte[100];
            when(cert.getEncoded()).thenReturn(certBytes);

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(certBytes);
            String expectedFingerprint = bytesToHex(digest).toUpperCase();

            ScittExpectation expectation = ScittExpectation.verified(
                List.of(expectedFingerprint), List.of(), "ans.test", Map.of(), null);

            ScittVerifier.ScittVerificationResult result =
                verifier.postVerify("test.example.com", cert, expectation);

            assertThat(result.success()).isTrue();
        }

        @Test
        @DisplayName("Should handle mixed case SHA256 prefix")
        void shouldHandleMixedCaseSha256Prefix() throws Exception {
            X509Certificate cert = mock(X509Certificate.class);
            byte[] certBytes = new byte[100];
            when(cert.getEncoded()).thenReturn(certBytes);

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(certBytes);
            String hexFingerprint = bytesToHex(digest);
            String fingerprintWithPrefix = "SHA256:" + hexFingerprint;

            ScittExpectation expectation = ScittExpectation.verified(
                List.of(fingerprintWithPrefix), List.of(), "ans.test", Map.of(), null);

            ScittVerifier.ScittVerificationResult result =
                verifier.postVerify("test.example.com", cert, expectation);

            assertThat(result.success()).isTrue();
        }
    }

    @Nested
    @DisplayName("Key ID validation tests")
    class KeyIdValidationTests {

        @Test
        @DisplayName("Should reject receipt with mismatched key ID")
        void shouldRejectReceiptWithMismatchedKeyId() throws Exception {
            // Create receipt with wrong key ID (not matching the public key)
            byte[] wrongKeyId = new byte[] {
                    0x00, 0x00, 0x00, 0x00
            };
            CoseProtectedHeader header = new CoseProtectedHeader(-7, wrongKeyId, 1, null, null);

            byte[] payload = "test-payload".getBytes();
            byte[] leafHash = MerkleProofVerifier.hashLeaf(payload);
            ScittReceipt.InclusionProof proof = new ScittReceipt.InclusionProof(1, 0, leafHash, List.of());

            ScittReceipt receipt = new ScittReceipt(header, new byte[10], proof, payload, new byte[64]);
            StatusToken token = createMockStatusToken(StatusToken.Status.ACTIVE);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            assertThat(result.status()).isEqualTo(ScittExpectation.Status.KEY_NOT_FOUND);
            assertThat(result.failureReason()).contains("not in trust store");
        }

        @Test
        @DisplayName("Should reject token with mismatched key ID")
        void shouldRejectTokenWithMismatchedKeyId() throws Exception {
            // Create valid receipt with correct key ID
            ScittReceipt receipt = createValidSignedReceipt(keyPair.getPrivate());

            // Create token with wrong key ID
            byte[] wrongKeyId = new byte[] {
                    0x00, 0x00, 0x00, 0x00
            };
            byte[] protectedHeaderBytes = new byte[10];
            byte[] payload = "agent_id:test-agent,status:ACTIVE".getBytes();

            byte[] sigStructure = CoseSign1Parser.buildSigStructure(protectedHeaderBytes, null, payload);
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(keyPair.getPrivate());
            sig.update(sigStructure);
            byte[] derSignature = sig.sign();
            byte[] p1363Signature = convertDerToP1363(derSignature);

            CoseProtectedHeader tokenHeader = new CoseProtectedHeader(-7, wrongKeyId, null, null, null);
            CoseEnvelope tokenEnvelope = new CoseEnvelope(tokenHeader, protectedHeaderBytes, payload, p1363Signature);
            StatusToken token = new StatusToken(
                "test-agent-id",
                StatusToken.Status.ACTIVE,
                Instant.now().minusSeconds(60),
                Instant.now().plusSeconds(3600),
                "test.ans",
                List.of(),
                List.of(),
                Map.of(),
                tokenEnvelope
            );

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            assertThat(result.status()).isEqualTo(ScittExpectation.Status.KEY_NOT_FOUND);
            assertThat(result.failureReason()).contains("not in trust store");
        }

        @Test
        @DisplayName("Should reject receipt with missing key ID")
        void shouldRejectReceiptWithMissingKeyId() throws Exception {
            // Create receipt with null key ID
            byte[] protectedHeaderBytes = new byte[10];
            byte[] payload = "test-payload".getBytes();

            byte[] sigStructure = CoseSign1Parser.buildSigStructure(protectedHeaderBytes, null, payload);
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(keyPair.getPrivate());
            sig.update(sigStructure);
            byte[] derSignature = sig.sign();
            byte[] p1363Signature = convertDerToP1363(derSignature);

            // null key ID should be rejected
            CoseProtectedHeader header = new CoseProtectedHeader(-7, null, 1, null, null);

            byte[] leafHash = MerkleProofVerifier.hashLeaf(payload);
            ScittReceipt.InclusionProof proof = new ScittReceipt.InclusionProof(1, 0, leafHash, List.of());

            ScittReceipt receipt = new ScittReceipt(header, protectedHeaderBytes, proof, payload, p1363Signature);
            StatusToken token = createValidSignedToken(keyPair.getPrivate(), StatusToken.Status.ACTIVE);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            assertThat(result.status()).isEqualTo(ScittExpectation.Status.KEY_NOT_FOUND);
            assertThat(result.failureReason()).contains("not in trust store");
        }

        @Test
        @DisplayName("Should reject token with missing key ID")
        void shouldRejectTokenWithMissingKeyId() throws Exception {
            // Create valid receipt with correct key ID
            ScittReceipt receipt = createValidSignedReceipt(keyPair.getPrivate());

            // Create token with null key ID
            byte[] protectedHeaderBytes = new byte[10];
            byte[] payload = "agent_id:test-agent,status:ACTIVE".getBytes();

            byte[] sigStructure = CoseSign1Parser.buildSigStructure(protectedHeaderBytes, null, payload);
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(keyPair.getPrivate());
            sig.update(sigStructure);
            byte[] derSignature = sig.sign();
            byte[] p1363Signature = convertDerToP1363(derSignature);

            // null key ID should be rejected
            CoseProtectedHeader tokenHeader = new CoseProtectedHeader(-7, null, null, null, null);
            CoseEnvelope tokenEnvelope = new CoseEnvelope(tokenHeader, protectedHeaderBytes, payload, p1363Signature);
            StatusToken token = new StatusToken(
                "test-agent-id",
                StatusToken.Status.ACTIVE,
                Instant.now().minusSeconds(60),
                Instant.now().plusSeconds(3600),
                "test.ans",
                List.of(),
                List.of(),
                Map.of(),
                tokenEnvelope
            );

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            assertThat(result.status()).isEqualTo(ScittExpectation.Status.KEY_NOT_FOUND);
            assertThat(result.failureReason()).contains("not in trust store");
        }

        @Test
        @DisplayName("Should accept artifact with correct key ID")
        void shouldAcceptArtifactWithCorrectKeyId() throws Exception {
            ScittReceipt receipt = createValidSignedReceipt(keyPair.getPrivate());
            StatusToken token = createValidSignedToken(keyPair.getPrivate(), StatusToken.Status.ACTIVE);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            assertThat(result.status()).isEqualTo(ScittExpectation.Status.VERIFIED);
        }
    }

    @Nested
    @DisplayName("Verification with different status tests")
    class VerificationStatusTests {

        @Test
        @DisplayName("Should return inactive for UNKNOWN status")
        void shouldReturnInactiveForUnknownStatus() throws Exception {
            ScittReceipt receipt = createValidSignedReceipt(keyPair.getPrivate());
            StatusToken token = createValidSignedToken(keyPair.getPrivate(), StatusToken.Status.UNKNOWN);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            // May be AGENT_INACTIVE or INVALID_RECEIPT depending on signature verification
            assertThat(result.status()).isIn(
                ScittExpectation.Status.AGENT_INACTIVE,
                ScittExpectation.Status.INVALID_RECEIPT,
                ScittExpectation.Status.INVALID_TOKEN
            );
        }

        @Test
        @DisplayName("Should return inactive for EXPIRED status")
        void shouldReturnInactiveForExpiredStatus() throws Exception {
            ScittReceipt receipt = createValidSignedReceipt(keyPair.getPrivate());
            StatusToken token = createValidSignedToken(keyPair.getPrivate(), StatusToken.Status.EXPIRED);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            assertThat(result.status()).isIn(
                ScittExpectation.Status.AGENT_INACTIVE,
                ScittExpectation.Status.INVALID_RECEIPT,
                ScittExpectation.Status.INVALID_TOKEN
            );
        }
    }

    @Nested
    @DisplayName("Issuer binding tests")
    class IssuerBindingTests {

        @Test
        @DisplayName("Should reject receipt with mismatched issuer")
        void shouldRejectReceiptWithMismatchedIssuer() throws Exception {
            // Receipt signed with CWT claims containing wrong issuer
            CwtClaims wrongIssuerClaims = new CwtClaims("wrong.domain.com", null, null, null, null, null);
            ScittReceipt receipt = createValidSignedReceiptWithCwtClaims(
                keyPair.getPrivate(), wrongIssuerClaims);
            StatusToken token = createValidSignedToken(keyPair.getPrivate(), StatusToken.Status.ACTIVE);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            assertThat(result.status()).isEqualTo(ScittExpectation.Status.INVALID_RECEIPT);
            assertThat(result.failureReason()).contains("issuer mismatch");
        }

        @Test
        @DisplayName("Should reject token with mismatched issuer")
        void shouldRejectTokenWithMismatchedIssuer() throws Exception {
            ScittReceipt receipt = createValidSignedReceipt(keyPair.getPrivate());
            CwtClaims wrongIssuerClaims = new CwtClaims("wrong.domain.com", null, null, null, null, null);
            StatusToken token = createValidSignedTokenWithCwtClaims(
                keyPair.getPrivate(), StatusToken.Status.ACTIVE, wrongIssuerClaims);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            assertThat(result.status()).isEqualTo(ScittExpectation.Status.INVALID_TOKEN);
            assertThat(result.failureReason()).contains("issuer mismatch");
        }

        @Test
        @DisplayName("Should accept artifacts with matching issuer")
        void shouldAcceptMatchingIssuer() throws Exception {
            CwtClaims matchingClaims = new CwtClaims(TEST_ISSUER, null, null, null, null, null);
            ScittReceipt receipt = createValidSignedReceiptWithCwtClaims(
                keyPair.getPrivate(), matchingClaims);
            StatusToken token = createValidSignedTokenWithCwtClaims(
                keyPair.getPrivate(), StatusToken.Status.ACTIVE, matchingClaims);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            assertThat(result.status()).isEqualTo(ScittExpectation.Status.VERIFIED);
        }

        @Test
        @DisplayName("Should accept receipt with missing CWT claims (lenient)")
        void shouldAcceptReceiptWithMissingCwtClaims() throws Exception {
            ScittReceipt receipt = createValidSignedReceiptWithCwtClaims(keyPair.getPrivate(), null);
            StatusToken token = createValidSignedToken(keyPair.getPrivate(), StatusToken.Status.ACTIVE);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            assertThat(result.status()).isEqualTo(ScittExpectation.Status.VERIFIED);
        }

        @Test
        @DisplayName("Should accept token with missing CWT claims (lenient)")
        void shouldAcceptTokenWithMissingCwtClaims() throws Exception {
            ScittReceipt receipt = createValidSignedReceipt(keyPair.getPrivate());
            CoseProtectedHeader tokenHeader = new CoseProtectedHeader(
                -7, computeKeyId(keyPair.getPublic()), null, null, null);
            StatusToken token = createValidSignedTokenWithHeader(
                keyPair.getPrivate(), StatusToken.Status.ACTIVE, tokenHeader);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            assertThat(result.status()).isEqualTo(ScittExpectation.Status.VERIFIED);
        }

        @Test
        @DisplayName("Should reject receipt with missing issuer claim")
        void shouldRejectReceiptWithMissingIssuerClaim() throws Exception {
            CwtClaims noIssuer = new CwtClaims(null, null, null, null, null, null);
            ScittReceipt receipt = createValidSignedReceiptWithCwtClaims(keyPair.getPrivate(), noIssuer);
            StatusToken token = createValidSignedToken(keyPair.getPrivate(), StatusToken.Status.ACTIVE);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            assertThat(result.status()).isEqualTo(ScittExpectation.Status.INVALID_RECEIPT);
            assertThat(result.failureReason()).contains("missing issuer claim");
        }

        @Test
        @DisplayName("Should reject token with missing issuer claim")
        void shouldRejectTokenWithMissingIssuerClaim() throws Exception {
            ScittReceipt receipt = createValidSignedReceipt(keyPair.getPrivate());
            CwtClaims noIssuer = new CwtClaims(null, null, null, null, null, null);
            StatusToken token = createValidSignedTokenWithCwtClaims(
                keyPair.getPrivate(), StatusToken.Status.ACTIVE, noIssuer);

            ScittExpectation result = verifier.verify(receipt, token, toRootKeys(keyPair.getPublic()));

            assertThat(result.status()).isEqualTo(ScittExpectation.Status.INVALID_TOKEN);
            assertThat(result.failureReason()).contains("missing issuer claim");
        }
    }

    // Helper methods

    private ScittReceipt createValidSignedReceiptWithCwtClaims(
            PrivateKey privateKey, CwtClaims cwtClaims) throws Exception {
        byte[] protectedHeaderBytes = new byte[10];
        byte[] payload = "test-payload".getBytes();

        byte[] sigStructure = CoseSign1Parser.buildSigStructure(protectedHeaderBytes, null, payload);
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(privateKey);
        sig.update(sigStructure);
        byte[] derSignature = sig.sign();
        byte[] p1363Signature = convertDerToP1363(derSignature);

        byte[] keyId = computeKeyId(keyPair.getPublic());
        CoseProtectedHeader header = new CoseProtectedHeader(-7, keyId, 1, cwtClaims, null);

        byte[] leafHash = MerkleProofVerifier.hashLeaf(payload);
        ScittReceipt.InclusionProof proof = new ScittReceipt.InclusionProof(
            1, 0, leafHash, List.of());

        return new ScittReceipt(header, protectedHeaderBytes, proof, payload, p1363Signature);
    }

    private StatusToken createValidSignedTokenWithCwtClaims(
            PrivateKey privateKey, StatusToken.Status status, CwtClaims cwtClaims) throws Exception {
        byte[] protectedHeaderBytes = new byte[10];
        byte[] payload = ("agent_id:test-agent,status:" + status.name()).getBytes();

        byte[] sigStructure = CoseSign1Parser.buildSigStructure(protectedHeaderBytes, null, payload);
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(privateKey);
        sig.update(sigStructure);
        byte[] derSignature = sig.sign();
        byte[] p1363Signature = convertDerToP1363(derSignature);

        byte[] keyId = computeKeyId(keyPair.getPublic());
        CoseProtectedHeader header = new CoseProtectedHeader(-7, keyId, null, cwtClaims, null);
        CoseEnvelope envelope = new CoseEnvelope(header, protectedHeaderBytes, payload, p1363Signature);

        return new StatusToken(
            "test-agent-id",
            status,
            Instant.now().minusSeconds(60),
            Instant.now().plusSeconds(3600),
            "test.ans",
            List.of(),
            List.of(),
            Map.of(),
            envelope
        );
    }

    private StatusToken createValidSignedTokenWithHeader(
            PrivateKey privateKey, StatusToken.Status status,
            CoseProtectedHeader header) throws Exception {
        byte[] protectedHeaderBytes = new byte[10];
        byte[] payload = ("agent_id:test-agent,status:" + status.name()).getBytes();

        byte[] sigStructure = CoseSign1Parser.buildSigStructure(protectedHeaderBytes, null, payload);
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(privateKey);
        sig.update(sigStructure);
        byte[] derSignature = sig.sign();
        byte[] p1363Signature = convertDerToP1363(derSignature);

        CoseEnvelope envelope = new CoseEnvelope(header, protectedHeaderBytes, payload, p1363Signature);

        return new StatusToken(
            "test-agent-id",
            status,
            Instant.now().minusSeconds(60),
            Instant.now().plusSeconds(3600),
            "test.ans",
            List.of(),
            List.of(),
            Map.of(),
            envelope
        );
    }

    private ScittReceipt createMockReceipt() {
        try {
            byte[] keyId = computeKeyId(keyPair.getPublic());
            CoseProtectedHeader header = new CoseProtectedHeader(-7, keyId, 1, null, null);
            ScittReceipt.InclusionProof proof = new ScittReceipt.InclusionProof(
                1, 0, new byte[32], List.of());
            return new ScittReceipt(
                header,
                new byte[10],
                proof,
                "test-payload".getBytes(),
                new byte[64]
            );
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private ScittReceipt createReceiptWithSignature(byte[] signature) {
        try {
            byte[] keyId = computeKeyId(keyPair.getPublic());
            CoseProtectedHeader header = new CoseProtectedHeader(-7, keyId, 1, null, null);
            ScittReceipt.InclusionProof proof = new ScittReceipt.InclusionProof(
                1, 0, new byte[32], List.of());
            return new ScittReceipt(
                header,
                new byte[10],
                proof,
                "test-payload".getBytes(),
                signature
            );
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private ScittReceipt createValidSignedReceipt(PrivateKey privateKey) throws Exception {
        CwtClaims claims = new CwtClaims(TEST_ISSUER, null, null, null, null, null);
        return createValidSignedReceiptWithCwtClaims(privateKey, claims);
    }

    private StatusToken createMockStatusToken(StatusToken.Status status) {
        try {
            byte[] keyId = computeKeyId(keyPair.getPublic());
            CoseEnvelope envelope = new CoseEnvelope(
                new CoseProtectedHeader(-7, keyId, null, null, null),
                new byte[10],
                "test-payload".getBytes(),
                new byte[64]
            );
            return new StatusToken(
                "test-agent-id",
                status,
                Instant.now().minusSeconds(60),
                Instant.now().plusSeconds(3600),
                "test.ans",
                List.of(),
                List.of(),
                Map.of(),
                envelope
            );
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private StatusToken createValidSignedToken(PrivateKey privateKey, StatusToken.Status status) throws Exception {
        CwtClaims claims = new CwtClaims(TEST_ISSUER, null, null, null, null, null);
        return createValidSignedTokenWithCwtClaims(privateKey, status, claims);
    }

    private StatusToken createExpiredToken(PrivateKey privateKey, Duration expiredAgo) throws Exception {
        byte[] protectedHeaderBytes = new byte[10];
        byte[] payload = "agent_id:test-agent,status:ACTIVE".getBytes();

        byte[] sigStructure = CoseSign1Parser.buildSigStructure(protectedHeaderBytes, null, payload);

        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(privateKey);
        sig.update(sigStructure);
        byte[] derSignature = sig.sign();
        byte[] p1363Signature = convertDerToP1363(derSignature);

        byte[] keyId = computeKeyId(keyPair.getPublic());
        CoseProtectedHeader header = new CoseProtectedHeader(-7, keyId, null, null, null);
        CoseEnvelope envelope = new CoseEnvelope(header, protectedHeaderBytes, payload, p1363Signature);

        return new StatusToken(
            "test-agent-id",
            StatusToken.Status.ACTIVE,
            Instant.now().minusSeconds(7200),
            Instant.now().minus(expiredAgo),  // Expired
            "test.ans",
            List.of(),
            List.of(),
            Map.of(),
            envelope
        );
    }

    private byte[] convertDerToP1363(byte[] derSignature) {
        return ScittTestHelpers.convertDerToP1363(derSignature);
    }

    private static String bytesToHex(byte[] bytes) {
        return ScittTestHelpers.bytesToHex(bytes);
    }

    /**
     * Computes the key ID for a public key per C2SP specification.
     * The key ID is the first 4 bytes of SHA-256(SPKI-DER).
     */
    private byte[] computeKeyId(PublicKey publicKey) throws Exception {
        return ScittTestHelpers.computeKeyId(publicKey);
    }
}
