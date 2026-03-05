package com.godaddy.ans.sdk.crypto;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcaPKCS8EncryptedPrivateKeyInfoBuilder;

import java.io.FileReader;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.KeyFactory;

/**
 * Utility class for generating and managing cryptographic key pairs.
 *
 * <p>This class provides methods for generating RSA and EC key pairs
 * suitable for use with ANS certificate requests.</p>
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * KeyPairManager keyManager = new KeyPairManager();
 * KeyPair identityKeyPair = keyManager.generateRsaKeyPair(2048);
 * KeyPair serverKeyPair = keyManager.generateRsaKeyPair(2048);
 * }</pre>
 */
public class KeyPairManager {

    static {
        // Register Bouncy Castle provider if not already registered
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Creates a new KeyPairManager instance.
     */
    public KeyPairManager() {
        // Default constructor
    }

    /**
     * Generates an RSA key pair with the specified key size.
     *
     * @param keySize the key size in bits (typically 2048 or 4096)
     * @return the generated key pair
     * @throws IllegalArgumentException if the key size is invalid
     * @throws RuntimeException if key generation fails
     */
    public KeyPair generateRsaKeyPair(int keySize) {
        if (keySize < 2048) {
            throw new IllegalArgumentException("RSA key size must be at least 2048 bits");
        }

        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            keyGen.initialize(keySize);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("Failed to generate RSA key pair", e);
        }
    }

    /**
     * Generates an RSA key pair with default key size (2048 bits).
     *
     * @return the generated key pair
     * @throws RuntimeException if key generation fails
     */
    public KeyPair generateRsaKeyPair() {
        return generateRsaKeyPair(2048);
    }

    /**
     * Generates an EC (Elliptic Curve) key pair using the specified curve.
     *
     * @param curveName the curve name (e.g., "secp256r1", "secp384r1")
     * @return the generated key pair
     * @throws IllegalArgumentException if the curve name is invalid
     * @throws RuntimeException if key generation fails
     */
    public KeyPair generateEcKeyPair(String curveName) {
        if (curveName == null || curveName.isBlank()) {
            throw new IllegalArgumentException("Curve name cannot be null or blank");
        }

        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            keyGen.initialize(new java.security.spec.ECGenParameterSpec(curveName));
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate EC key pair with curve: " + curveName, e);
        }
    }

    /**
     * Generates an EC key pair using the P-256 curve (secp256r1).
     *
     * @return the generated key pair
     * @throws RuntimeException if key generation fails
     */
    public KeyPair generateEcKeyPair() {
        return generateEcKeyPair("secp256r1");
    }

    // ==================== PEM Storage Methods ====================

    /**
     * Saves a private key to a PEM file.
     *
     * <p>If a password is provided, the key will be encrypted using AES-256-CBC.
     * If password is null, the key will be saved unencrypted.</p>
     *
     * @param keyPair the key pair containing the private key to save
     * @param filePath the path to save the PEM file
     * @param password optional password for encryption (null for unencrypted)
     * @throws RuntimeException if saving fails
     */
    public void savePrivateKeyToPem(KeyPair keyPair, Path filePath, String password) {
        if (keyPair == null) {
            throw new IllegalArgumentException("Key pair cannot be null");
        }
        if (filePath == null) {
            throw new IllegalArgumentException("File path cannot be null");
        }

        try {
            // Ensure parent directory exists
            Path parent = filePath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }

            String pemContent = getPrivateKeyAsPem(keyPair, password);
            Files.writeString(filePath, pemContent);
        } catch (IOException e) {
            throw new RuntimeException("Failed to save private key to PEM file: " + filePath, e);
        }
    }

    /**
     * Saves a private key to a PEM file (convenience method with String path).
     *
     * @param keyPair the key pair containing the private key to save
     * @param filePath the path to save the PEM file
     * @param password optional password for encryption (null for unencrypted)
     * @throws RuntimeException if saving fails
     */
    public void savePrivateKeyToPem(KeyPair keyPair, String filePath, String password) {
        savePrivateKeyToPem(keyPair, Path.of(filePath), password);
    }

    /**
     * Gets a private key as a PEM-formatted string.
     *
     * <p>If a password is provided, the key will be encrypted using PKCS#8 with AES-256-CBC.
     * If password is null, the key will be returned unencrypted in PKCS#8 format.</p>
     *
     * @param keyPair the key pair containing the private key
     * @param password optional password for encryption (null for unencrypted)
     * @return the private key in PEM format
     * @throws RuntimeException if conversion fails
     */
    public String getPrivateKeyAsPem(KeyPair keyPair, String password) {
        if (keyPair == null) {
            throw new IllegalArgumentException("Key pair cannot be null");
        }

        try {
            StringWriter stringWriter = new StringWriter();
            try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
                if (password != null && !password.isEmpty()) {
                    // Encrypt with PKCS#8 and AES-256-CBC
                    JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder =
                        new JceOpenSSLPKCS8EncryptorBuilder(
                                org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_aes256_CBC);
                    encryptorBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
                    encryptorBuilder.setPassword(password.toCharArray());
                    OutputEncryptor encryptor = encryptorBuilder.build();

                    PKCS8EncryptedPrivateKeyInfo encryptedInfo =
                        new JcaPKCS8EncryptedPrivateKeyInfoBuilder(keyPair.getPrivate())
                            .build(encryptor);
                    pemWriter.writeObject(encryptedInfo);
                } else {
                    // Write unencrypted PKCS#8 format using PemObject directly
                    org.bouncycastle.util.io.pem.PemObject pemObject =
                        new org.bouncycastle.util.io.pem.PemObject("PRIVATE KEY", keyPair.getPrivate().getEncoded());
                    pemWriter.writeObject(pemObject);
                }
            }
            return stringWriter.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert private key to PEM format", e);
        }
    }

    /**
     * Gets a private key as an unencrypted PEM-formatted string.
     *
     * @param keyPair the key pair containing the private key
     * @return the private key in PEM format (unencrypted)
     * @throws RuntimeException if conversion fails
     */
    public String getPrivateKeyAsPem(KeyPair keyPair) {
        return getPrivateKeyAsPem(keyPair, null);
    }

    /**
     * Loads a key pair from a PEM file containing a private key.
     *
     * <p>The public key is derived from the private key. Supports both encrypted
     * and unencrypted PEM files.</p>
     *
     * @param filePath the path to the PEM file
     * @param password the password if the key is encrypted (null for unencrypted)
     * @return the loaded key pair
     * @throws RuntimeException if loading fails
     */
    public KeyPair loadKeyPairFromPem(Path filePath, String password) {
        if (filePath == null) {
            throw new IllegalArgumentException("File path cannot be null");
        }
        if (!Files.exists(filePath)) {
            throw new IllegalArgumentException("PEM file does not exist: " + filePath);
        }

        try (PEMParser pemParser = new PEMParser(new FileReader(filePath.toFile()))) {
            Object pemObject = pemParser.readObject();
            return convertPemObjectToKeyPair(pemObject, password);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load key pair from PEM file: " + filePath, e);
        }
    }

    /**
     * Loads a key pair from a PEM file (convenience method with String path).
     *
     * @param filePath the path to the PEM file
     * @param password the password if the key is encrypted (null for unencrypted)
     * @return the loaded key pair
     * @throws RuntimeException if loading fails
     */
    public KeyPair loadKeyPairFromPem(String filePath, String password) {
        return loadKeyPairFromPem(Path.of(filePath), password);
    }

    /**
     * Converts a PEM object to a KeyPair.
     */
    private KeyPair convertPemObjectToKeyPair(Object pemObject, String password) {
        try {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME);

            PrivateKey privateKey;

            if (pemObject instanceof PKCS8EncryptedPrivateKeyInfo encryptedInfo) {
                // Encrypted PKCS#8 private key
                if (password == null || password.isEmpty()) {
                    throw new IllegalArgumentException("Password required for encrypted private key");
                }
                PrivateKeyInfo keyInfo = encryptedInfo.decryptPrivateKeyInfo(
                    new JceOpenSSLPKCS8DecryptorProviderBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(password.toCharArray())
                );
                privateKey = converter.getPrivateKey(keyInfo);
            } else if (pemObject instanceof PEMEncryptedKeyPair encryptedKeyPair) {
                // Encrypted traditional OpenSSL format
                if (password == null || password.isEmpty()) {
                    throw new IllegalArgumentException("Password required for encrypted private key");
                }
                PEMKeyPair decryptedKeyPair = encryptedKeyPair.decryptKeyPair(
                    new JcePEMDecryptorProviderBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(password.toCharArray())
                );
                return converter.getKeyPair(decryptedKeyPair);
            } else if (pemObject instanceof PEMKeyPair pemKeyPair) {
                // Unencrypted traditional OpenSSL format (includes public key)
                return converter.getKeyPair(pemKeyPair);
            } else if (pemObject instanceof PrivateKeyInfo keyInfo) {
                // Unencrypted PKCS#8 private key
                privateKey = converter.getPrivateKey(keyInfo);
            } else {
                throw new RuntimeException("Unsupported PEM object type: " +
                    (pemObject != null ? pemObject.getClass().getName() : "null"));
            }

            // Derive public key from private key
            PublicKey publicKey = derivePublicKey(privateKey);
            return new KeyPair(publicKey, privateKey);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert PEM object to KeyPair", e);
        }
    }

    /**
     * Derives the public key from a private key.
     */
    private PublicKey derivePublicKey(PrivateKey privateKey) {
        try {
            String algorithm = privateKey.getAlgorithm();
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);

            if ("RSA".equals(algorithm)) {
                java.security.interfaces.RSAPrivateCrtKey rsaPrivateKey =
                    (java.security.interfaces.RSAPrivateCrtKey) privateKey;
                java.security.spec.RSAPublicKeySpec publicKeySpec =
                    new java.security.spec.RSAPublicKeySpec(
                        rsaPrivateKey.getModulus(),
                        rsaPrivateKey.getPublicExponent()
                    );
                return keyFactory.generatePublic(publicKeySpec);
            } else if ("EC".equals(algorithm) || "ECDSA".equals(algorithm)) {
                java.security.interfaces.ECPrivateKey ecPrivateKey =
                    (java.security.interfaces.ECPrivateKey) privateKey;
                org.bouncycastle.jce.spec.ECParameterSpec bcSpec =
                    org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util.convertSpec(
                        ecPrivateKey.getParams()
                    );
                org.bouncycastle.math.ec.ECPoint q = bcSpec.getG().multiply(ecPrivateKey.getS());
                org.bouncycastle.jce.spec.ECPublicKeySpec publicKeySpec =
                    new org.bouncycastle.jce.spec.ECPublicKeySpec(q, bcSpec);
                return keyFactory.generatePublic(publicKeySpec);
            } else {
                throw new RuntimeException("Unsupported key algorithm for public key derivation: " + algorithm);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive public key from private key", e);
        }
    }

    /**
     * Saves the public key to a PEM file.
     *
     * @param keyPair the key pair containing the public key to save
     * @param filePath the path to save the PEM file
     * @throws RuntimeException if saving fails
     */
    public void savePublicKeyToPem(KeyPair keyPair, Path filePath) {
        if (keyPair == null) {
            throw new IllegalArgumentException("Key pair cannot be null");
        }
        if (filePath == null) {
            throw new IllegalArgumentException("File path cannot be null");
        }

        try {
            Path parent = filePath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }

            StringWriter stringWriter = new StringWriter();
            try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
                pemWriter.writeObject(keyPair.getPublic());
            }
            Files.writeString(filePath, stringWriter.toString());
        } catch (IOException e) {
            throw new RuntimeException("Failed to save public key to PEM file: " + filePath, e);
        }
    }

    /**
     * Saves the public key to a PEM file (convenience method with String path).
     *
     * @param keyPair the key pair containing the public key to save
     * @param filePath the path to save the PEM file
     * @throws RuntimeException if saving fails
     */
    public void savePublicKeyToPem(KeyPair keyPair, String filePath) {
        savePublicKeyToPem(keyPair, Path.of(filePath));
    }
}