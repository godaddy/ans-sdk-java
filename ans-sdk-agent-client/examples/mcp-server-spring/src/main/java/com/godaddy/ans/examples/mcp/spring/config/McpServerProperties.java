package com.godaddy.ans.examples.mcp.spring.config;

import com.godaddy.ans.sdk.agent.VerificationPolicy;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for the ANS MCP server.
 *
 * <p>Configurable via application.yml with prefix {@code ans.mcp}.</p>
 */
@ConfigurationProperties(prefix = "ans.mcp")
public class McpServerProperties {

    /**
     * Agent UUID for SCITT artifact fetching from the Transparency Log.
     */
    private String agentId;

    /**
     * Server identification.
     */
    private ServerInfo serverInfo = new ServerInfo();

    /**
     * Client verification settings.
     */
    private Verification verification = new Verification();

    /**
     * SCITT configuration.
     */
    private Scitt scitt = new Scitt();

    public String getAgentId() {
        return agentId;
    }

    public void setAgentId(String agentId) {
        this.agentId = agentId;
    }

    public ServerInfo getServerInfo() {
        return serverInfo;
    }

    public void setServerInfo(ServerInfo serverInfo) {
        this.serverInfo = serverInfo;
    }

    public Verification getVerification() {
        return verification;
    }

    public void setVerification(Verification verification) {
        this.verification = verification;
    }

    public Scitt getScitt() {
        return scitt;
    }

    public void setScitt(Scitt scitt) {
        this.scitt = scitt;
    }

    /**
     * Server identification settings.
     */
    public static class ServerInfo {
        private String name = "ans-mcp-server";
        private String version = "1.0.0";

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getVersion() {
            return version;
        }

        public void setVersion(String version) {
            this.version = version;
        }
    }

    /**
     * Client verification settings.
     */
    public static class Verification {
        /**
         * Whether to enable client verification.
         */
        private boolean enabled = true;

        /**
         * Verification policy name. Supported values:
         * - PKI_ONLY: No additional verification beyond TLS
         * - SCITT_REQUIRED: Require valid SCITT artifacts (recommended for production)
         * - SCITT_ENHANCED: SCITT with badge fallback
         */
        private String policy = "SCITT_REQUIRED";

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getPolicy() {
            return policy;
        }

        public void setPolicy(String policy) {
            this.policy = policy;
        }

        /**
         * Returns the verification policy instance based on the configured policy name.
         */
        public VerificationPolicy getVerificationPolicy() {
            return switch (policy.toUpperCase()) {
                case "PKI_ONLY" -> VerificationPolicy.PKI_ONLY;
                case "BADGE_REQUIRED" -> VerificationPolicy.BADGE_REQUIRED;
                case "DANE_ADVISORY" -> VerificationPolicy.DANE_ADVISORY;
                case "DANE_REQUIRED" -> VerificationPolicy.DANE_REQUIRED;
                case "DANE_AND_BADGE" -> VerificationPolicy.DANE_AND_BADGE;
                case "SCITT_ENHANCED" -> VerificationPolicy.SCITT_ENHANCED;
                case "SCITT_REQUIRED" -> VerificationPolicy.SCITT_REQUIRED;
                default -> throw new IllegalArgumentException("Unknown verification policy: " + policy);
            };
        }
    }

    /**
     * SCITT configuration settings.
     */
    public static class Scitt {
        /**
         * Transparency Log domain for SCITT operations.
         * Default is OTE (testing environment).
         */
        private String domain = "transparency.ans.ote-godaddy.com";

        public String getDomain() {
            return domain;
        }

        public void setDomain(String domain) {
            this.domain = domain;
        }
    }
}
