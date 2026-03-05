package com.godaddy.ans.sdk.crypto;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * Utility class for generating Certificate Signing Requests (CSRs).
 *
 * <p>This class provides methods for generating CSRs in PEM format,
 * suitable for submission to the ANS Registry for certificate issuance.</p>
 *
 * <p>For ANS Registry registration, use the specialized methods:</p>
 * <ul>
 *   <li>{@link #generateServerCsr(KeyPair, String)} - For server/TLS certificates</li>
 *   <li>{@link #generateIdentityCsr(KeyPair, String, String)} - For identity certificates</li>
 * </ul>
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * CsrGenerator csrGenerator = new CsrGenerator();
 *
 * // For server certificate (TLS)
 * String serverCsr = csrGenerator.generateServerCsr(keyPair, "my-agent.example.com");
 *
 * // For identity certificate (ANS name URI is constructed automatically)
 * String identityCsr = csrGenerator.generateIdentityCsr(
 *     keyPair,
 *     "my-agent.example.com",  // agentHost
 *     "1.0.0"                  // version -> creates SAN URI: ans://v1.0.0.my-agent.example.com
 * );
 * }</pre>
 */
public class CsrGenerator {

    private static final String RSA_SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String EC_SIGNATURE_ALGORITHM = "SHA256withECDSA";

    static {
        // Register Bouncy Castle provider if not already registered
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Creates a new CsrGenerator instance.
     */
    public CsrGenerator() {
        // Default constructor
    }

    /**
     * Generates a CSR in PEM format.
     *
     * @param keyPair the key pair to use for the CSR
     * @param subjectDn the subject distinguished name (e.g., "CN=my-agent.example.com")
     * @return the CSR in PEM format
     * @throws RuntimeException if CSR generation fails
     */
    public String generateCsr(KeyPair keyPair, String subjectDn) {
        return generateCsr(keyPair, subjectDn, null);
    }

    /**
     * Generates a CSR in PEM format with Subject Alternative Names (SANs).
     *
     * @param keyPair the key pair to use for the CSR
     * @param subjectDn the subject distinguished name (e.g., "CN=my-agent.example.com")
     * @param sanDnsNames optional list of DNS names for the SAN extension
     * @return the CSR in PEM format
     * @throws RuntimeException if CSR generation fails
     */
    public String generateCsr(KeyPair keyPair, String subjectDn, List<String> sanDnsNames) {
        if (keyPair == null) {
            throw new IllegalArgumentException("Key pair cannot be null");
        }
        if (subjectDn == null || subjectDn.isBlank()) {
            throw new IllegalArgumentException("Subject DN cannot be null or blank");
        }

        try {
            X500Name subject = new X500Name(subjectDn);
            PKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

            // Add SAN extension if DNS names are provided
            if (sanDnsNames != null && !sanDnsNames.isEmpty()) {
                ExtensionsGenerator extGen = new ExtensionsGenerator();
                List<GeneralName> generalNames = new ArrayList<>();
                for (String dnsName : sanDnsNames) {
                    generalNames.add(new GeneralName(GeneralName.dNSName, dnsName));
                }
                extGen.addExtension(
                    Extension.subjectAlternativeName,
                    false,
                    new GeneralNames(generalNames.toArray(new GeneralName[0]))
                );
                csrBuilder.addAttribute(
                    PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                    extGen.generate()
                );
            }

            // Determine signature algorithm based on key type
            String signatureAlgorithm = determineSignatureAlgorithm(keyPair);

            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());

            PKCS10CertificationRequest csr = csrBuilder.build(signer);

            return toPemString(csr);
        } catch (OperatorCreationException | IOException e) {
            throw new RuntimeException("Failed to generate CSR", e);
        }
    }

    // ==================== ANS Registry Specialized Methods ====================

    /**
     * Generates a server/TLS CSR for ANS Registry registration.
     *
     * <p>This method creates a CSR with:</p>
     * <ul>
     *   <li>CN (Common Name) set to the agent host</li>
     *   <li>SAN DNS entry matching the agent host</li>
     * </ul>
     *
     * <p>The ANS Registry requires the SAN DNS to match the CN for server certificates.</p>
     *
     * @param keyPair the key pair to use for the CSR
     * @param agentHost the agent's host name (e.g., "my-agent.example.com")
     * @return the CSR in PEM format
     * @throws IllegalArgumentException if keyPair or agentHost is null/blank
     * @throws RuntimeException if CSR generation fails
     */
    public String generateServerCsr(KeyPair keyPair, String agentHost) {
        if (agentHost == null || agentHost.isBlank()) {
            throw new IllegalArgumentException("Agent host cannot be null or blank");
        }

        String subjectDn = "CN=" + agentHost;
        List<String> sanDnsNames = List.of(agentHost);

        return generateCsr(keyPair, subjectDn, sanDnsNames);
    }

    /**
     * Generates an identity CSR for ANS Registry registration.
     *
     * <p>This method creates a CSR with:</p>
     * <ul>
     *   <li>CN (Common Name) set to the agent host</li>
     *   <li>SAN DNS entry matching the agent host</li>
     *   <li>SAN URI entry with the ANS name (automatically constructed as {@code ans://v{version}.{agentHost}})</li>
     * </ul>
     *
     * <p>The ANS Registry requires identity certificates to include the ANS name
     * as a URI in the Subject Alternative Name extension.</p>
     *
     * @param keyPair the key pair to use for the CSR
     * @param agentHost the agent's host name (e.g., "my-agent.example.com")
     * @param version the agent version (e.g., "1.0.0")
     * @return the CSR in PEM format
     * @throws IllegalArgumentException if any parameter is null/blank
     * @throws RuntimeException if CSR generation fails
     */
    public String generateIdentityCsr(KeyPair keyPair, String agentHost, String version) {
        if (keyPair == null) {
            throw new IllegalArgumentException("Key pair cannot be null");
        }
        if (agentHost == null || agentHost.isBlank()) {
            throw new IllegalArgumentException("Agent host cannot be null or blank");
        }
        if (version == null || version.isBlank()) {
            throw new IllegalArgumentException("Version cannot be null or blank");
        }

        // Construct the ANS name URI: ans://v{version}.{agentHost}
        String ansName = "ans://v" + version + "." + agentHost;

        try {
            String subjectDn = "CN=" + agentHost;
            X500Name subject = new X500Name(subjectDn);
            PKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

            // Add SAN extension with both DNS name and URI
            ExtensionsGenerator extGen = new ExtensionsGenerator();
            List<GeneralName> generalNames = new ArrayList<>();

            // Add DNS name (required to match CN)
            generalNames.add(new GeneralName(GeneralName.dNSName, agentHost));

            // Add URI for ANS name (required for identity certificates)
            generalNames.add(new GeneralName(GeneralName.uniformResourceIdentifier, ansName));

            extGen.addExtension(
                Extension.subjectAlternativeName,
                false,
                new GeneralNames(generalNames.toArray(new GeneralName[0]))
            );
            csrBuilder.addAttribute(
                PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                extGen.generate()
            );

            // Determine signature algorithm based on key type
            String signatureAlgorithm = determineSignatureAlgorithm(keyPair);

            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());

            PKCS10CertificationRequest csr = csrBuilder.build(signer);

            return toPemString(csr);
        } catch (OperatorCreationException | IOException e) {
            throw new RuntimeException("Failed to generate identity CSR", e);
        }
    }

    /**
     * Determines the appropriate signature algorithm based on the key type.
     */
    private String determineSignatureAlgorithm(KeyPair keyPair) {
        String algorithm = keyPair.getPrivate().getAlgorithm();
        return switch (algorithm) {
            case "RSA" -> RSA_SIGNATURE_ALGORITHM;
            case "EC", "ECDSA" -> EC_SIGNATURE_ALGORITHM;
            default -> throw new IllegalArgumentException("Unsupported key algorithm: " + algorithm);
        };
    }

    /**
     * Converts a CSR to PEM format string.
     */
    private String toPemString(PKCS10CertificationRequest csr) throws IOException {
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(csr);
        }
        return stringWriter.toString();
    }
}