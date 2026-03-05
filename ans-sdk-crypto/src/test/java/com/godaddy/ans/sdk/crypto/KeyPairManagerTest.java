package com.godaddy.ans.sdk.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;

import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for KeyPairManager.
 */
class KeyPairManagerTest {

    private KeyPairManager keyPairManager;

    @BeforeEach
    void setUp() {
        keyPairManager = new KeyPairManager();
    }

    // ==================== RSA Key Pair Tests ====================

    @Test
    @DisplayName("Should generate RSA key pair with default size (2048 bits)")
    void shouldGenerateRsaKeyPairWithDefaultSize() {
        KeyPair keyPair = keyPairManager.generateRsaKeyPair();

        assertThat(keyPair).isNotNull();
        assertThat(keyPair.getPublic()).isInstanceOf(RSAPublicKey.class);
        assertThat(keyPair.getPrivate()).isNotNull();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        assertThat(publicKey.getModulus().bitLength()).isEqualTo(2048);
    }

    @Test
    @DisplayName("Should generate RSA key pair with 4096 bits")
    void shouldGenerateRsaKeyPairWith4096Bits() {
        KeyPair keyPair = keyPairManager.generateRsaKeyPair(4096);

        assertThat(keyPair).isNotNull();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        assertThat(publicKey.getModulus().bitLength()).isEqualTo(4096);
    }

    @Test
    @DisplayName("Should reject RSA key size less than 2048")
    void shouldRejectRsaKeySizeLessThan2048() {
        assertThatThrownBy(() -> keyPairManager.generateRsaKeyPair(1024))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("at least 2048");
    }

    @Test
    @DisplayName("RSA key pair should have correct algorithm")
    void rsaKeyPairShouldHaveCorrectAlgorithm() {
        KeyPair keyPair = keyPairManager.generateRsaKeyPair();

        assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("RSA");
        assertThat(keyPair.getPrivate().getAlgorithm()).isEqualTo("RSA");
    }

    // ==================== EC Key Pair Tests ====================

    @Test
    @DisplayName("Should generate EC key pair with default curve (P-256)")
    void shouldGenerateEcKeyPairWithDefaultCurve() {
        KeyPair keyPair = keyPairManager.generateEcKeyPair();

        assertThat(keyPair).isNotNull();
        assertThat(keyPair.getPublic()).isInstanceOf(ECPublicKey.class);
        assertThat(keyPair.getPrivate()).isNotNull();
    }

    @Test
    @DisplayName("Should generate EC key pair with secp384r1 curve")
    void shouldGenerateEcKeyPairWithP384Curve() {
        KeyPair keyPair = keyPairManager.generateEcKeyPair("secp384r1");

        assertThat(keyPair).isNotNull();
        assertThat(keyPair.getPublic()).isInstanceOf(ECPublicKey.class);
    }

    @Test
    @DisplayName("Should reject null curve name")
    void shouldRejectNullCurveName() {
        assertThatThrownBy(() -> keyPairManager.generateEcKeyPair(null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("null or blank");
    }

    @Test
    @DisplayName("Should reject blank curve name")
    void shouldRejectBlankCurveName() {
        assertThatThrownBy(() -> keyPairManager.generateEcKeyPair("   "))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("null or blank");
    }

    @Test
    @DisplayName("EC key pair should have correct algorithm")
    void ecKeyPairShouldHaveCorrectAlgorithm() {
        KeyPair keyPair = keyPairManager.generateEcKeyPair();

        assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("EC");
        assertThat(keyPair.getPrivate().getAlgorithm()).isEqualTo("EC");
    }

    // ==================== General Tests ====================

    @Test
    @DisplayName("Should generate unique key pairs")
    void shouldGenerateUniqueKeyPairs() {
        KeyPair keyPair1 = keyPairManager.generateRsaKeyPair();
        KeyPair keyPair2 = keyPairManager.generateRsaKeyPair();

        assertThat(keyPair1.getPublic().getEncoded())
            .isNotEqualTo(keyPair2.getPublic().getEncoded());
    }

    // ==================== PEM Storage Tests - RSA ====================

    @Test
    @DisplayName("Should save and load unencrypted RSA private key")
    void shouldSaveAndLoadUnencryptedRsaPrivateKey(@TempDir Path tempDir) {
        KeyPair originalKeyPair = keyPairManager.generateRsaKeyPair();
        Path pemFile = tempDir.resolve("rsa-private.pem");

        // Save
        keyPairManager.savePrivateKeyToPem(originalKeyPair, pemFile, null);

        // Verify file exists and has PEM format
        assertThat(Files.exists(pemFile)).isTrue();
        assertThat(pemFile).content().startsWith("-----BEGIN PRIVATE KEY-----");

        // Load and verify
        KeyPair loadedKeyPair = keyPairManager.loadKeyPairFromPem(pemFile, null);

        assertThat(loadedKeyPair).isNotNull();
        assertThat(loadedKeyPair.getPrivate().getEncoded())
            .isEqualTo(originalKeyPair.getPrivate().getEncoded());
        assertThat(loadedKeyPair.getPublic().getEncoded())
            .isEqualTo(originalKeyPair.getPublic().getEncoded());
    }

    @Test
    @DisplayName("Should save and load encrypted RSA private key")
    void shouldSaveAndLoadEncryptedRsaPrivateKey(@TempDir Path tempDir) {
        KeyPair originalKeyPair = keyPairManager.generateRsaKeyPair();
        Path pemFile = tempDir.resolve("rsa-private-encrypted.pem");
        String password = "test-password-123";

        // Save with encryption
        keyPairManager.savePrivateKeyToPem(originalKeyPair, pemFile, password);

        // Verify file exists and has encrypted PEM format
        assertThat(Files.exists(pemFile)).isTrue();
        assertThat(pemFile).content().startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----");

        // Load and verify
        KeyPair loadedKeyPair = keyPairManager.loadKeyPairFromPem(pemFile, password);

        assertThat(loadedKeyPair).isNotNull();
        assertThat(loadedKeyPair.getPrivate().getEncoded())
            .isEqualTo(originalKeyPair.getPrivate().getEncoded());
        assertThat(loadedKeyPair.getPublic().getEncoded())
            .isEqualTo(originalKeyPair.getPublic().getEncoded());
    }

    @Test
    @DisplayName("Should fail to load encrypted RSA key with wrong password")
    void shouldFailToLoadEncryptedRsaKeyWithWrongPassword(@TempDir Path tempDir) {
        KeyPair originalKeyPair = keyPairManager.generateRsaKeyPair();
        Path pemFile = tempDir.resolve("rsa-private-encrypted.pem");

        keyPairManager.savePrivateKeyToPem(originalKeyPair, pemFile, "correct-password");

        assertThatThrownBy(() -> keyPairManager.loadKeyPairFromPem(pemFile, "wrong-password"))
            .isInstanceOf(RuntimeException.class);
    }

    @Test
    @DisplayName("Should fail to load encrypted RSA key without password")
    void shouldFailToLoadEncryptedRsaKeyWithoutPassword(@TempDir Path tempDir) {
        KeyPair originalKeyPair = keyPairManager.generateRsaKeyPair();
        Path pemFile = tempDir.resolve("rsa-private-encrypted.pem");

        keyPairManager.savePrivateKeyToPem(originalKeyPair, pemFile, "test-password");

        assertThatThrownBy(() -> keyPairManager.loadKeyPairFromPem(pemFile, null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Password required");
    }

    // ==================== PEM Storage Tests - EC ====================

    @Test
    @DisplayName("Should save and load unencrypted EC private key")
    void shouldSaveAndLoadUnencryptedEcPrivateKey(@TempDir Path tempDir) {
        KeyPair originalKeyPair = keyPairManager.generateEcKeyPair();
        Path pemFile = tempDir.resolve("ec-private.pem");

        // Save
        keyPairManager.savePrivateKeyToPem(originalKeyPair, pemFile, null);

        // Verify file exists
        assertThat(Files.exists(pemFile)).isTrue();

        // Load and verify
        KeyPair loadedKeyPair = keyPairManager.loadKeyPairFromPem(pemFile, null);

        assertThat(loadedKeyPair).isNotNull();
        assertThat(loadedKeyPair.getPrivate().getEncoded())
            .isEqualTo(originalKeyPair.getPrivate().getEncoded());
        assertThat(loadedKeyPair.getPublic().getEncoded())
            .isEqualTo(originalKeyPair.getPublic().getEncoded());
    }

    @Test
    @DisplayName("Should save and load encrypted EC private key")
    void shouldSaveAndLoadEncryptedEcPrivateKey(@TempDir Path tempDir) {
        KeyPair originalKeyPair = keyPairManager.generateEcKeyPair();
        Path pemFile = tempDir.resolve("ec-private-encrypted.pem");
        String password = "ec-test-password";

        // Save with encryption
        keyPairManager.savePrivateKeyToPem(originalKeyPair, pemFile, password);

        // Verify file exists
        assertThat(Files.exists(pemFile)).isTrue();

        // Load and verify
        KeyPair loadedKeyPair = keyPairManager.loadKeyPairFromPem(pemFile, password);

        assertThat(loadedKeyPair).isNotNull();
        assertThat(loadedKeyPair.getPrivate().getEncoded())
            .isEqualTo(originalKeyPair.getPrivate().getEncoded());
        assertThat(loadedKeyPair.getPublic().getEncoded())
            .isEqualTo(originalKeyPair.getPublic().getEncoded());
    }

    // ==================== PEM Storage Tests - Public Key ====================

    @Test
    @DisplayName("Should save public key to PEM file")
    void shouldSavePublicKeyToPem(@TempDir Path tempDir) {
        KeyPair keyPair = keyPairManager.generateRsaKeyPair();
        Path pemFile = tempDir.resolve("public-key.pem");

        keyPairManager.savePublicKeyToPem(keyPair, pemFile);

        assertThat(Files.exists(pemFile)).isTrue();
        assertThat(pemFile).content().startsWith("-----BEGIN PUBLIC KEY-----");
    }

    // ==================== PEM Storage Tests - String Path ====================

    @Test
    @DisplayName("Should work with String file paths")
    void shouldWorkWithStringFilePaths(@TempDir Path tempDir) {
        KeyPair originalKeyPair = keyPairManager.generateRsaKeyPair();
        String pemFilePath = tempDir.resolve("string-path.pem").toString();

        // Save using String path
        keyPairManager.savePrivateKeyToPem(originalKeyPair, pemFilePath, null);

        // Load using String path
        KeyPair loadedKeyPair = keyPairManager.loadKeyPairFromPem(pemFilePath, null);

        assertThat(loadedKeyPair.getPrivate().getEncoded())
            .isEqualTo(originalKeyPair.getPrivate().getEncoded());
    }

    // ==================== PEM Storage Tests - Get as String ====================

    @Test
    @DisplayName("Should get private key as unencrypted PEM string")
    void shouldGetPrivateKeyAsUnencryptedPemString() {
        KeyPair keyPair = keyPairManager.generateRsaKeyPair();

        String pem = keyPairManager.getPrivateKeyAsPem(keyPair);

        assertThat(pem).isNotNull();
        assertThat(pem).startsWith("-----BEGIN PRIVATE KEY-----");
        assertThat(pem).contains("-----END PRIVATE KEY-----");
    }

    @Test
    @DisplayName("Should get private key as encrypted PEM string")
    void shouldGetPrivateKeyAsEncryptedPemString() {
        KeyPair keyPair = keyPairManager.generateRsaKeyPair();

        String pem = keyPairManager.getPrivateKeyAsPem(keyPair, "test-password");

        assertThat(pem).isNotNull();
        assertThat(pem).startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----");
        assertThat(pem).contains("-----END ENCRYPTED PRIVATE KEY-----");
    }

    // ==================== PEM Storage Tests - Validation ====================

    @Test
    @DisplayName("Should reject null key pair when saving")
    void shouldRejectNullKeyPairWhenSaving(@TempDir Path tempDir) {
        Path pemFile = tempDir.resolve("test.pem");

        assertThatThrownBy(() -> keyPairManager.savePrivateKeyToPem(null, pemFile, null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Key pair cannot be null");
    }

    @Test
    @DisplayName("Should reject null file path when saving")
    void shouldRejectNullFilePathWhenSaving() {
        KeyPair keyPair = keyPairManager.generateRsaKeyPair();

        assertThatThrownBy(() -> keyPairManager.savePrivateKeyToPem(keyPair, (Path) null, null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("File path cannot be null");
    }

    @Test
    @DisplayName("Should reject non-existent file when loading")
    void shouldRejectNonExistentFileWhenLoading(@TempDir Path tempDir) {
        Path nonExistent = tempDir.resolve("does-not-exist.pem");

        assertThatThrownBy(() -> keyPairManager.loadKeyPairFromPem(nonExistent, null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("does not exist");
    }

    @Test
    @DisplayName("Should create parent directories when saving")
    void shouldCreateParentDirectoriesWhenSaving(@TempDir Path tempDir) {
        KeyPair keyPair = keyPairManager.generateRsaKeyPair();
        Path nestedPath = tempDir.resolve("nested/dir/key.pem");

        keyPairManager.savePrivateKeyToPem(keyPair, nestedPath, null);

        assertThat(Files.exists(nestedPath)).isTrue();
    }

    // ==================== Additional Coverage Tests ====================

    @Test
    @DisplayName("Should reject invalid EC curve name")
    void shouldRejectInvalidEcCurveName() {
        assertThatThrownBy(() -> keyPairManager.generateEcKeyPair("invalid-curve"))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("Failed to generate EC key pair");
    }

    @Test
    @DisplayName("Should save public key to PEM file with String path")
    void shouldSavePublicKeyToPemWithStringPath(@TempDir Path tempDir) {
        KeyPair keyPair = keyPairManager.generateRsaKeyPair();
        String pemFilePath = tempDir.resolve("public-key-string.pem").toString();

        keyPairManager.savePublicKeyToPem(keyPair, pemFilePath);

        assertThat(Files.exists(Path.of(pemFilePath))).isTrue();
    }

    @Test
    @DisplayName("Should reject null file path when loading")
    void shouldRejectNullFilePathWhenLoading() {
        assertThatThrownBy(() -> keyPairManager.loadKeyPairFromPem((Path) null, null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("File path cannot be null");
    }

    @Test
    @DisplayName("Should reject null key pair when getting PEM string")
    void shouldRejectNullKeyPairWhenGettingPemString() {
        assertThatThrownBy(() -> keyPairManager.getPrivateKeyAsPem(null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Key pair cannot be null");
    }

    @Test
    @DisplayName("Should reject null key pair when getting encrypted PEM string")
    void shouldRejectNullKeyPairWhenGettingEncryptedPemString() {
        assertThatThrownBy(() -> keyPairManager.getPrivateKeyAsPem(null, "password"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Key pair cannot be null");
    }

    @Test
    @DisplayName("Should reject null key pair when saving public key")
    void shouldRejectNullKeyPairWhenSavingPublicKey(@TempDir Path tempDir) {
        Path pemFile = tempDir.resolve("public.pem");

        assertThatThrownBy(() -> keyPairManager.savePublicKeyToPem(null, pemFile))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Key pair cannot be null");
    }

    @Test
    @DisplayName("Should reject null file path when saving public key")
    void shouldRejectNullFilePathWhenSavingPublicKey() {
        KeyPair keyPair = keyPairManager.generateRsaKeyPair();

        assertThatThrownBy(() -> keyPairManager.savePublicKeyToPem(keyPair, (Path) null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("File path cannot be null");
    }

    @Test
    @DisplayName("Should create parent directories when saving public key")
    void shouldCreateParentDirectoriesWhenSavingPublicKey(@TempDir Path tempDir) {
        KeyPair keyPair = keyPairManager.generateRsaKeyPair();
        Path nestedPath = tempDir.resolve("nested/public/key.pem");

        keyPairManager.savePublicKeyToPem(keyPair, nestedPath);

        assertThat(Files.exists(nestedPath)).isTrue();
    }

    @Test
    @DisplayName("Should save public key for EC key pair")
    void shouldSavePublicKeyForEcKeyPair(@TempDir Path tempDir) {
        KeyPair keyPair = keyPairManager.generateEcKeyPair();
        Path pemFile = tempDir.resolve("ec-public.pem");

        keyPairManager.savePublicKeyToPem(keyPair, pemFile);

        assertThat(Files.exists(pemFile)).isTrue();
        assertThat(pemFile).content().startsWith("-----BEGIN PUBLIC KEY-----");
    }

    @Test
    @DisplayName("Should handle empty password as unencrypted")
    void shouldHandleEmptyPasswordAsUnencrypted(@TempDir Path tempDir) {
        KeyPair originalKeyPair = keyPairManager.generateRsaKeyPair();
        Path pemFile = tempDir.resolve("empty-password.pem");

        // Save with empty password (should save unencrypted)
        keyPairManager.savePrivateKeyToPem(originalKeyPair, pemFile, "");

        // Verify file has unencrypted format
        assertThat(pemFile).content().startsWith("-----BEGIN PRIVATE KEY-----");

        // Load and verify
        KeyPair loadedKeyPair = keyPairManager.loadKeyPairFromPem(pemFile, null);
        assertThat(loadedKeyPair.getPrivate().getEncoded())
            .isEqualTo(originalKeyPair.getPrivate().getEncoded());
    }

    @Test
    @DisplayName("Should fail to load encrypted key with empty password")
    void shouldFailToLoadEncryptedKeyWithEmptyPassword(@TempDir Path tempDir) {
        KeyPair originalKeyPair = keyPairManager.generateRsaKeyPair();
        Path pemFile = tempDir.resolve("encrypted-empty-pass.pem");

        keyPairManager.savePrivateKeyToPem(originalKeyPair, pemFile, "password");

        assertThatThrownBy(() -> keyPairManager.loadKeyPairFromPem(pemFile, ""))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Password required");
    }

    // ==================== Traditional OpenSSL Format Tests ====================

    @Test
    @DisplayName("Should load unencrypted traditional OpenSSL RSA key")
    void shouldLoadUnencryptedTraditionalOpenSslRsaKey(@TempDir Path tempDir) throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        KeyPair originalKeyPair = keyPairManager.generateRsaKeyPair();
        Path pemFile = tempDir.resolve("traditional-rsa.pem");

        // Write in traditional OpenSSL format (RSA PRIVATE KEY)
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            pemWriter.writeObject(originalKeyPair.getPrivate());
        }
        Files.writeString(pemFile, sw.toString());

        // Load and verify
        KeyPair loadedKeyPair = keyPairManager.loadKeyPairFromPem(pemFile, null);

        assertThat(loadedKeyPair).isNotNull();
        assertThat(loadedKeyPair.getPrivate().getAlgorithm()).isEqualTo("RSA");
        assertThat(loadedKeyPair.getPublic().getAlgorithm()).isEqualTo("RSA");
    }

    @Test
    @DisplayName("Should load encrypted traditional OpenSSL RSA key")
    void shouldLoadEncryptedTraditionalOpenSslRsaKey(@TempDir Path tempDir) throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        KeyPair originalKeyPair = keyPairManager.generateRsaKeyPair();
        Path pemFile = tempDir.resolve("traditional-rsa-encrypted.pem");
        String password = "test-password";

        // Write in traditional OpenSSL encrypted format (ENCRYPTED RSA PRIVATE KEY)
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            JcePEMEncryptorBuilder encryptorBuilder = new JcePEMEncryptorBuilder("AES-256-CBC");
            encryptorBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            pemWriter.writeObject(originalKeyPair.getPrivate(), encryptorBuilder.build(password.toCharArray()));
        }
        Files.writeString(pemFile, sw.toString());

        // Load and verify
        KeyPair loadedKeyPair = keyPairManager.loadKeyPairFromPem(pemFile, password);

        assertThat(loadedKeyPair).isNotNull();
        assertThat(loadedKeyPair.getPrivate().getAlgorithm()).isEqualTo("RSA");
        assertThat(loadedKeyPair.getPublic().getAlgorithm()).isEqualTo("RSA");
    }

    @Test
    @DisplayName("Should fail to load encrypted traditional OpenSSL key without password")
    void shouldFailToLoadEncryptedTraditionalOpenSslKeyWithoutPassword(@TempDir Path tempDir) throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        KeyPair originalKeyPair = keyPairManager.generateRsaKeyPair();
        Path pemFile = tempDir.resolve("traditional-rsa-encrypted-nopass.pem");
        String password = "test-password";

        // Write in traditional OpenSSL encrypted format
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            JcePEMEncryptorBuilder encryptorBuilder = new JcePEMEncryptorBuilder("AES-256-CBC");
            encryptorBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            pemWriter.writeObject(originalKeyPair.getPrivate(), encryptorBuilder.build(password.toCharArray()));
        }
        Files.writeString(pemFile, sw.toString());

        // Attempt to load without password
        assertThatThrownBy(() -> keyPairManager.loadKeyPairFromPem(pemFile, null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Password required");
    }

    @Test
    @DisplayName("Should load unencrypted traditional OpenSSL EC key")
    void shouldLoadUnencryptedTraditionalOpenSslEcKey(@TempDir Path tempDir) throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        KeyPair originalKeyPair = keyPairManager.generateEcKeyPair();
        Path pemFile = tempDir.resolve("traditional-ec.pem");

        // Write in traditional OpenSSL format (EC PRIVATE KEY)
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            pemWriter.writeObject(originalKeyPair.getPrivate());
        }
        Files.writeString(pemFile, sw.toString());

        // Load and verify - just check that it loads successfully
        KeyPair loadedKeyPair = keyPairManager.loadKeyPairFromPem(pemFile, null);

        assertThat(loadedKeyPair).isNotNull();
        assertThat(loadedKeyPair.getPrivate()).isNotNull();
        assertThat(loadedKeyPair.getPublic()).isNotNull();
    }

    @Test
    @DisplayName("Should fail to load unsupported PEM format")
    void shouldFailToLoadUnsupportedPemFormat(@TempDir Path tempDir) throws Exception {
        Path pemFile = tempDir.resolve("unsupported.pem");

        // Write a PEM file with unsupported content (certificate instead of key)
        String unsupportedPem = """
            -----BEGIN CERTIFICATE REQUEST-----
            MIIBPTCB5AIBADBgMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExEjAQBgNVBAcM
            CVNvbWV3aGVyZTENMAsGA1UECgwEVGVzdDENMAsGA1UECwwEVGVzdDESMBAGA1UE
            AwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb7NRNs8zP48P
            6Hb2s+MFNmXKVT5cIYqGqTFEoU8LqLkXnI3RbGv7xqf8dL7azS5Fw2s+vvspHEaI
            x2D3G2YXWKAAMAoGCCqGSM49BAMCA0gAMEUCIQCVzS8vxlXvLXoB/I8JkLMKwLJ+
            gZm7H3J3pJmZZQIgG2s6z3j3F3hWbG3kPkQM2Q8S7nL6F3kZqN5Z3Q3Q==
            -----END CERTIFICATE REQUEST-----
            """;
        Files.writeString(pemFile, unsupportedPem);

        assertThatThrownBy(() -> keyPairManager.loadKeyPairFromPem(pemFile, null))
            .isInstanceOf(RuntimeException.class);
    }

    @Test
    @DisplayName("Should fail to save private key to non-writable location")
    void shouldFailToSavePrivateKeyToNonWritableLocation(@TempDir Path tempDir) throws Exception {
        KeyPair keyPair = keyPairManager.generateRsaKeyPair();
        // Try to write to a path that doesn't exist and can't be created
        Path invalidPath = Path.of("/nonexistent/directory/that/does/not/exist/key.pem");

        assertThatThrownBy(() -> keyPairManager.savePrivateKeyToPem(keyPair, invalidPath, null))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("Failed to save private key");
    }

    @Test
    @DisplayName("Should fail to save public key to non-writable location")
    void shouldFailToSavePublicKeyToNonWritableLocation(@TempDir Path tempDir) throws Exception {
        KeyPair keyPair = keyPairManager.generateRsaKeyPair();
        // Try to write to a path that doesn't exist and can't be created
        Path invalidPath = Path.of("/nonexistent/directory/that/does/not/exist/key.pem");

        assertThatThrownBy(() -> keyPairManager.savePublicKeyToPem(keyPair, invalidPath))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("Failed to save public key");
    }

    @Test
    @DisplayName("Should fail to load PEM with corrupted content")
    void shouldFailToLoadPemWithCorruptedContent(@TempDir Path tempDir) throws Exception {
        Path pemFile = tempDir.resolve("corrupted.pem");

        // Write a corrupted PEM file
        String corruptedPem = "-----BEGIN PRIVATE KEY-----\nthis is not valid base64!\n-----END PRIVATE KEY-----";
        Files.writeString(pemFile, corruptedPem);

        assertThatThrownBy(() -> keyPairManager.loadKeyPairFromPem(pemFile, null))
            .isInstanceOf(RuntimeException.class);
    }

    @Test
    @DisplayName("Should fail to load encrypted PEM with wrong password")
    void shouldFailToLoadEncryptedPemWithWrongPassword(@TempDir Path tempDir) throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        KeyPair originalKeyPair = keyPairManager.generateRsaKeyPair();
        Path pemFile = tempDir.resolve("wrong-pass.pem");

        // Write encrypted traditional OpenSSL format
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            JcePEMEncryptorBuilder encryptorBuilder = new JcePEMEncryptorBuilder("AES-256-CBC");
            encryptorBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            pemWriter.writeObject(originalKeyPair.getPrivate(), encryptorBuilder.build("correct".toCharArray()));
        }
        Files.writeString(pemFile, sw.toString());

        // Try to load with wrong password
        assertThatThrownBy(() -> keyPairManager.loadKeyPairFromPem(pemFile, "wrong"))
            .isInstanceOf(RuntimeException.class);
    }
}