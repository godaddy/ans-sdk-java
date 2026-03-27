package com.godaddy.ans.sdk.crypto;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * Utility class for working with X.509 certificates.
 *
 * <p>This class provides methods for parsing, validating, and converting
 * certificates between different formats.</p>
 */
public final class CertificateUtils {

    static {
        // Register Bouncy Castle provider if not already registered
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private CertificateUtils() {
        // Utility class
    }

    /**
     * Parses a PEM-encoded certificate.
     *
     * @param pemCertificate the PEM-encoded certificate string
     * @return the parsed X509Certificate
     * @throws RuntimeException if parsing fails
     */
    public static X509Certificate parseCertificate(String pemCertificate) {
        if (pemCertificate == null || pemCertificate.isBlank()) {
            throw new IllegalArgumentException("PEM certificate cannot be null or blank");
        }

        try (PEMParser parser = new PEMParser(new StringReader(pemCertificate))) {
            Object obj = parser.readObject();
            if (obj instanceof X509CertificateHolder holder) {
                return new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(holder);
            }
            throw new RuntimeException("Invalid certificate format");
        } catch (IOException | CertificateException e) {
            throw new RuntimeException("Failed to parse certificate", e);
        }
    }

    /**
     * Parses a PEM-encoded certificate chain.
     *
     * @param pemChain the PEM-encoded certificate chain string
     * @return list of parsed certificates, in the order they appear in the chain
     * @throws RuntimeException if parsing fails
     */
    public static List<X509Certificate> parseCertificateChain(String pemChain) {
        if (pemChain == null || pemChain.isBlank()) {
            throw new IllegalArgumentException("PEM chain cannot be null or blank");
        }

        List<X509Certificate> certificates = new ArrayList<>();
        try (PEMParser parser = new PEMParser(new StringReader(pemChain))) {
            Object obj;
            while ((obj = parser.readObject()) != null) {
                if (obj instanceof X509CertificateHolder holder) {
                    certificates.add(
                        new JcaX509CertificateConverter()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .getCertificate(holder)
                    );
                }
            }
        } catch (IOException | CertificateException e) {
            throw new RuntimeException("Failed to parse certificate chain", e);
        }

        if (certificates.isEmpty()) {
            throw new RuntimeException("No certificates found in chain");
        }

        return certificates;
    }

    /**
     * Converts a certificate to PEM format.
     *
     * @param certificate the certificate to convert
     * @return the PEM-encoded certificate string
     * @throws RuntimeException if conversion fails
     */
    public static String toPem(X509Certificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate cannot be null");
        }

        try (StringWriter stringWriter = new StringWriter();
             JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(certificate);
            pemWriter.flush();
            return stringWriter.toString();
        } catch (IOException e) {
            throw new RuntimeException("Failed to convert certificate to PEM", e);
        }
    }

    /**
     * Checks if a certificate is currently valid (not expired and not before valid period).
     *
     * @param certificate the certificate to check
     * @return true if the certificate is currently valid
     */
    public static boolean isValid(X509Certificate certificate) {
        if (certificate == null) {
            return false;
        }
        Date now = new Date();
        return now.after(certificate.getNotBefore()) && now.before(certificate.getNotAfter());
    }

    /**
     * Checks if a certificate will expire within the specified number of days.
     *
     * @param certificate the certificate to check
     * @param days the number of days
     * @return true if the certificate will expire within the specified days
     */
    public static boolean expiresWithinDays(X509Certificate certificate, int days) {
        if (certificate == null) {
            return true;
        }
        long daysInMillis = days * 24L * 60L * 60L * 1000L;
        Date futureDate = new Date(System.currentTimeMillis() + daysInMillis);
        return certificate.getNotAfter().before(futureDate);
    }

    /**
     * Gets the common name (CN) from a certificate's subject.
     *
     * <p>Uses BouncyCastle's DN parser for robust extraction that properly handles
     * escaped characters, multiple RDNs, and different orderings.</p>
     *
     * @param certificate the certificate
     * @return the common name, or null if not found
     */
    public static String getCommonName(X509Certificate certificate) {
        if (certificate == null) {
            return null;
        }
        try {
            JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder(certificate);
            X500Name subject = certHolder.getSubject();
            RDN[] rdns = subject.getRDNs(BCStyle.CN);
            if (rdns.length > 0) {
                return rdns[0].getFirst().getValue().toString();
            }
            return null;
        } catch (Exception e) {
            // Fall back to null if parsing fails
            return null;
        }
    }

    /**
     * Gets the serial number of a certificate as a string.
     *
     * @param certificate the certificate
     * @return the serial number in hexadecimal format
     */
    public static String getSerialNumber(X509Certificate certificate) {
        if (certificate == null) {
            return null;
        }
        return certificate.getSerialNumber().toString(16);
    }

    /**
     * Computes the SHA-256 fingerprint of a certificate.
     *
     * @param certificate the certificate
     * @return the fingerprint in format "SHA256:hex-encoded-hash"
     * @throws RuntimeException if fingerprint computation fails
     */
    public static String computeSha256Fingerprint(X509Certificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate cannot be null");
        }
        try {
            byte[] digest = CryptoCache.sha256(certificate.getEncoded());
            StringBuilder hex = new StringBuilder("SHA256:");
            for (byte b : digest) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (CertificateEncodingException e) {
            throw new RuntimeException("Failed to compute certificate fingerprint", e);
        }
    }

    /**
     * Compares two fingerprints for equality, handling format differences.
     *
     * <p>This method handles fingerprints with or without the "SHA256:" prefix
     * and is case-insensitive.</p>
     *
     * @param actual the actual fingerprint
     * @param expected the expected fingerprint
     * @return true if the fingerprints match
     */
    public static boolean fingerprintMatches(String actual, String expected) {
        if (actual == null || expected == null) {
            return false;
        }
        // Normalize: remove prefix, lowercase
        String normalizedActual = normalizeFingerprint(actual);
        String normalizedExpected = normalizeFingerprint(expected);
        return normalizedActual.equals(normalizedExpected);
    }

    public static String normalizeFingerprint(String fingerprint) {
        String normalized = fingerprint.toLowerCase().trim();
        // Remove common prefixes
        if (normalized.startsWith("sha256:")) {
            normalized = normalized.substring(7);
        } else if (normalized.startsWith("sha-256:")) {
            normalized = normalized.substring(8);
        }
        // Remove colons and spaces
        return normalized.replace(":", "").replace(" ", "");
    }

    /**
     * Extracts the FQDN from a certificate.
     *
     * <p>This method first checks DNS Subject Alternative Names, then falls back
     * to the Common Name (CN) if no DNS SAN is present.</p>
     *
     * @param certificate the certificate
     * @return the FQDN, or empty if not found
     */
    public static Optional<String> extractFqdn(X509Certificate certificate) {
        if (certificate == null) {
            return Optional.empty();
        }

        // First try DNS SANs
        List<String> dnsNames = getDnsSubjectAltNames(certificate);
        if (!dnsNames.isEmpty()) {
            return Optional.of(dnsNames.get(0));
        }

        // Fall back to CN
        String cn = getCommonName(certificate);
        return Optional.ofNullable(cn);
    }

    /**
     * Extracts the ANS name from a certificate's URI Subject Alternative Name.
     *
     * <p>ANS names are stored in URI SANs and start with "ans://".</p>
     *
     * @param certificate the certificate
     * @return the ANS name, or empty if not found
     */
    public static Optional<String> extractAnsName(X509Certificate certificate) {
        if (certificate == null) {
            return Optional.empty();
        }

        List<String> uris = getUriSubjectAltNames(certificate);
        for (String uri : uris) {
            if (uri != null && uri.toLowerCase().startsWith("ans://")) {
                return Optional.of(uri);
            }
        }
        return Optional.empty();
    }

    /**
     * Gets DNS Subject Alternative Names from a certificate.
     *
     * @param certificate the certificate
     * @return list of DNS names, empty if none
     */
    public static List<String> getDnsSubjectAltNames(X509Certificate certificate) {
        return getSubjectAltNames(certificate, 2); // 2 = DNS Name
    }

    /**
     * Gets URI Subject Alternative Names from a certificate.
     *
     * @param certificate the certificate
     * @return list of URIs, empty if none
     */
    public static List<String> getUriSubjectAltNames(X509Certificate certificate) {
        return getSubjectAltNames(certificate, 6); // 6 = URI
    }

    /**
     * Gets Subject Alternative Names of a specific type.
     *
     * @param certificate the certificate
     * @param type the SAN type (2=DNS, 6=URI, etc.)
     * @return list of SANs, empty if none
     */
    private static List<String> getSubjectAltNames(X509Certificate certificate, int type) {
        if (certificate == null) {
            return Collections.emptyList();
        }
        try {
            Collection<List<?>> sans = certificate.getSubjectAlternativeNames();
            if (sans == null) {
                return Collections.emptyList();
            }
            List<String> result = new ArrayList<>();
            for (List<?> san : sans) {
                if (san.size() >= 2 && Integer.valueOf(type).equals(san.get(0))) {
                    Object value = san.get(1);
                    if (value instanceof String) {
                        result.add((String) value);
                    }
                }
            }
            return result;
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }
}