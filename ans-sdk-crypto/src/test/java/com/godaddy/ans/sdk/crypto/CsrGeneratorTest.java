package com.godaddy.ans.sdk.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.security.KeyPair;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for CsrGenerator.
 */
class CsrGeneratorTest {

    private CsrGenerator csrGenerator;
    private KeyPairManager keyPairManager;
    private KeyPair rsaKeyPair;
    private KeyPair ecKeyPair;

    @BeforeEach
    void setUp() {
        csrGenerator = new CsrGenerator();
        keyPairManager = new KeyPairManager();
        rsaKeyPair = keyPairManager.generateRsaKeyPair();
        ecKeyPair = keyPairManager.generateEcKeyPair();
    }

    // ==================== Basic CSR Generation Tests ====================

    @Test
    @DisplayName("Should generate CSR with RSA key pair")
    void shouldGenerateCsrWithRsaKeyPair() {
        String csr = csrGenerator.generateCsr(rsaKeyPair, "CN=test-agent.example.com");

        assertThat(csr).isNotNull();
        assertThat(csr).startsWith("-----BEGIN CERTIFICATE REQUEST-----");
        assertThat(csr).contains("-----END CERTIFICATE REQUEST-----");
    }

    @Test
    @DisplayName("Should generate CSR with EC key pair")
    void shouldGenerateCsrWithEcKeyPair() {
        String csr = csrGenerator.generateCsr(ecKeyPair, "CN=test-agent.example.com");

        assertThat(csr).isNotNull();
        assertThat(csr).startsWith("-----BEGIN CERTIFICATE REQUEST-----");
        assertThat(csr).contains("-----END CERTIFICATE REQUEST-----");
    }

    @Test
    @DisplayName("Should generate CSR with full subject DN")
    void shouldGenerateCsrWithFullSubjectDn() {
        String subjectDn = "CN=test-agent.example.com,O=GoDaddy,L=Tempe,ST=Arizona,C=US";
        String csr = csrGenerator.generateCsr(rsaKeyPair, subjectDn);

        assertThat(csr).isNotNull();
        assertThat(csr).startsWith("-----BEGIN CERTIFICATE REQUEST-----");
    }

    // ==================== SAN Extension Tests ====================

    @Test
    @DisplayName("Should generate CSR with SAN DNS names")
    void shouldGenerateCsrWithSanDnsNames() {
        List<String> sanDnsNames = Arrays.asList(
            "test-agent.example.com",
            "www.test-agent.example.com"
        );

        String csr = csrGenerator.generateCsr(rsaKeyPair, "CN=test-agent.example.com", sanDnsNames);

        assertThat(csr).isNotNull();
        assertThat(csr).startsWith("-----BEGIN CERTIFICATE REQUEST-----");
    }

    @Test
    @DisplayName("Should generate CSR with null SAN list")
    void shouldGenerateCsrWithNullSanList() {
        String csr = csrGenerator.generateCsr(rsaKeyPair, "CN=test-agent.example.com", null);

        assertThat(csr).isNotNull();
        assertThat(csr).startsWith("-----BEGIN CERTIFICATE REQUEST-----");
    }

    @Test
    @DisplayName("Should generate CSR with empty SAN list")
    void shouldGenerateCsrWithEmptySanList() {
        String csr = csrGenerator.generateCsr(rsaKeyPair, "CN=test-agent.example.com", List.of());

        assertThat(csr).isNotNull();
        assertThat(csr).startsWith("-----BEGIN CERTIFICATE REQUEST-----");
    }

    // ==================== Validation Tests ====================

    @Test
    @DisplayName("Should reject null key pair")
    void shouldRejectNullKeyPair() {
        assertThatThrownBy(() -> csrGenerator.generateCsr(null, "CN=test.example.com"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Key pair cannot be null");
    }

    @Test
    @DisplayName("Should reject null subject DN")
    void shouldRejectNullSubjectDn() {
        assertThatThrownBy(() -> csrGenerator.generateCsr(rsaKeyPair, null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Subject DN cannot be null or blank");
    }

    @Test
    @DisplayName("Should reject blank subject DN")
    void shouldRejectBlankSubjectDn() {
        assertThatThrownBy(() -> csrGenerator.generateCsr(rsaKeyPair, "   "))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Subject DN cannot be null or blank");
    }

    // ==================== PEM Format Tests ====================

    @Test
    @DisplayName("CSR should be in valid PEM format")
    void csrShouldBeInValidPemFormat() {
        String csr = csrGenerator.generateCsr(rsaKeyPair, "CN=test.example.com");

        // Verify PEM structure
        String[] lines = csr.split("\n");
        assertThat(lines[0].trim()).isEqualTo("-----BEGIN CERTIFICATE REQUEST-----");
        assertThat(lines[lines.length - 1].trim()).isEqualTo("-----END CERTIFICATE REQUEST-----");

        // Verify base64 content exists between headers
        assertThat(lines.length).isGreaterThan(2);
    }

    @Test
    @DisplayName("Each generated CSR should be unique")
    void eachGeneratedCsrShouldBeUnique() {
        KeyPair keyPair1 = keyPairManager.generateRsaKeyPair();
        KeyPair keyPair2 = keyPairManager.generateRsaKeyPair();

        String csr1 = csrGenerator.generateCsr(keyPair1, "CN=test1.example.com");
        String csr2 = csrGenerator.generateCsr(keyPair2, "CN=test2.example.com");

        assertThat(csr1).isNotEqualTo(csr2);
    }

    // ==================== ANS Registry Server CSR Tests ====================

    @Test
    @DisplayName("Should generate server CSR with correct structure")
    void shouldGenerateServerCsr() {
        String agentHost = "my-agent.example.com";
        String csr = csrGenerator.generateServerCsr(rsaKeyPair, agentHost);

        assertThat(csr).isNotNull();
        assertThat(csr).startsWith("-----BEGIN CERTIFICATE REQUEST-----");
        assertThat(csr).contains("-----END CERTIFICATE REQUEST-----");
    }

    @Test
    @DisplayName("Should generate server CSR with EC key pair")
    void shouldGenerateServerCsrWithEcKeyPair() {
        String agentHost = "my-agent.example.com";
        String csr = csrGenerator.generateServerCsr(ecKeyPair, agentHost);

        assertThat(csr).isNotNull();
        assertThat(csr).startsWith("-----BEGIN CERTIFICATE REQUEST-----");
    }

    @Test
    @DisplayName("Should reject null agent host for server CSR")
    void shouldRejectNullAgentHostForServerCsr() {
        assertThatThrownBy(() -> csrGenerator.generateServerCsr(rsaKeyPair, null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Agent host cannot be null or blank");
    }

    @Test
    @DisplayName("Should reject blank agent host for server CSR")
    void shouldRejectBlankAgentHostForServerCsr() {
        assertThatThrownBy(() -> csrGenerator.generateServerCsr(rsaKeyPair, "   "))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Agent host cannot be null or blank");
    }

    // ==================== ANS Registry Identity CSR Tests ====================

    @Test
    @DisplayName("Should generate identity CSR with correct structure")
    void shouldGenerateIdentityCsr() {
        String agentHost = "my-agent.example.com";
        String version = "1.0.0";
        String csr = csrGenerator.generateIdentityCsr(rsaKeyPair, agentHost, version);

        assertThat(csr).isNotNull();
        assertThat(csr).startsWith("-----BEGIN CERTIFICATE REQUEST-----");
        assertThat(csr).contains("-----END CERTIFICATE REQUEST-----");
    }

    @Test
    @DisplayName("Should generate identity CSR with EC key pair")
    void shouldGenerateIdentityCsrWithEcKeyPair() {
        String agentHost = "my-agent.example.com";
        String version = "1.0.0";
        String csr = csrGenerator.generateIdentityCsr(ecKeyPair, agentHost, version);

        assertThat(csr).isNotNull();
        assertThat(csr).startsWith("-----BEGIN CERTIFICATE REQUEST-----");
    }

    @Test
    @DisplayName("Should reject null key pair for identity CSR")
    void shouldRejectNullKeyPairForIdentityCsr() {
        assertThatThrownBy(() -> csrGenerator.generateIdentityCsr(
            null, "my-agent.example.com", "1.0.0"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Key pair cannot be null");
    }

    @Test
    @DisplayName("Should reject null agent host for identity CSR")
    void shouldRejectNullAgentHostForIdentityCsr() {
        assertThatThrownBy(() -> csrGenerator.generateIdentityCsr(
            rsaKeyPair, null, "1.0.0"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Agent host cannot be null or blank");
    }

    @Test
    @DisplayName("Should reject blank agent host for identity CSR")
    void shouldRejectBlankAgentHostForIdentityCsr() {
        assertThatThrownBy(() -> csrGenerator.generateIdentityCsr(
            rsaKeyPair, "   ", "1.0.0"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Agent host cannot be null or blank");
    }

    @Test
    @DisplayName("Should reject null version for identity CSR")
    void shouldRejectNullVersionForIdentityCsr() {
        assertThatThrownBy(() -> csrGenerator.generateIdentityCsr(
            rsaKeyPair, "my-agent.example.com", null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Version cannot be null or blank");
    }

    @Test
    @DisplayName("Should reject blank version for identity CSR")
    void shouldRejectBlankVersionForIdentityCsr() {
        assertThatThrownBy(() -> csrGenerator.generateIdentityCsr(
            rsaKeyPair, "my-agent.example.com", "   "))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Version cannot be null or blank");
    }

    @Test
    @DisplayName("Server and identity CSRs should be different")
    void serverAndIdentityCsrsShouldBeDifferent() {
        String agentHost = "my-agent.example.com";
        String version = "1.0.0";

        String serverCsr = csrGenerator.generateServerCsr(rsaKeyPair, agentHost);
        String identityCsr = csrGenerator.generateIdentityCsr(rsaKeyPair, agentHost, version);

        // They should be different because identity CSR has an additional SAN URI
        assertThat(serverCsr).isNotEqualTo(identityCsr);
    }
}