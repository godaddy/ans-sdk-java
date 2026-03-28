package com.godaddy.ans.sdk.discovery;

import com.godaddy.ans.sdk.auth.AnsCredentials;
import com.godaddy.ans.sdk.auth.AnsCredentialsProvider;
import com.godaddy.ans.sdk.config.AnsConfiguration;
import com.godaddy.ans.sdk.exception.AnsServerException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ResolutionService}.
 */
class ResolutionServiceTest {

    private ResolutionService resolutionService;

    @BeforeEach
    void setUp() {
        AnsCredentials mockCredentials = mock(AnsCredentials.class);
        when(mockCredentials.toAuthorizationHeader()).thenReturn("Bearer test-token");

        AnsCredentialsProvider mockProvider = mock(AnsCredentialsProvider.class);
        when(mockProvider.resolveCredentials()).thenReturn(mockCredentials);

        AnsConfiguration config = AnsConfiguration.builder()
            .environment(com.godaddy.ans.sdk.config.Environment.OTE)
            .credentialsProvider(mockProvider)
            .baseUrl("https://api.example.com")
            .build();

        resolutionService = new ResolutionService(config);
    }

    // ==================== Path Validation Tests ====================

    @Test
    @DisplayName("Should accept valid agent-details path")
    void shouldAcceptValidAgentDetailsPath() throws Exception {
        // Given - valid response with proper path
        String responseBody = """
            {
                "links": [
                    {"rel": "agent-details", "href": "/v1/agents/abc123-def456"}
                ]
            }
            """;

        // When
        String path = invokeExtractAgentDetailsLink(responseBody);

        // Then
        assertThat(path).isEqualTo("/v1/agents/abc123-def456");
    }

    @Test
    @DisplayName("Should accept valid absolute URL with proper path")
    void shouldAcceptValidAbsoluteUrlWithProperPath() throws Exception {
        // Given - absolute URL with valid path
        String responseBody = """
            {
                "links": [
                    {"rel": "agent-details", "href": "https://api.example.com/v1/agents/abc123"}
                ]
            }
            """;

        // When
        String path = invokeExtractAgentDetailsLink(responseBody);

        // Then
        assertThat(path).isEqualTo("/v1/agents/abc123");
    }

    @Test
    @DisplayName("Should reject path that doesn't start with /v1/agents/")
    void shouldRejectPathThatDoesNotStartWithExpectedPrefix() throws Exception {
        // Given - malicious response with unexpected path
        String responseBody = """
            {
                "links": [
                    {"rel": "agent-details", "href": "/admin/delete-all"}
                ]
            }
            """;

        // When/Then - should reject the invalid path
        Throwable thrown = catchThrowable(() -> invokeExtractAgentDetailsLink(responseBody));
        assertThat(thrown).isInstanceOf(InvocationTargetException.class);
        assertThat(thrown.getCause())
            .isInstanceOf(AnsServerException.class)
            .hasMessageContaining("Invalid agent-details link");
    }

    @Test
    @DisplayName("Should reject absolute URL with unexpected path")
    void shouldRejectAbsoluteUrlWithUnexpectedPath() throws Exception {
        // Given - absolute URL with malicious path
        String responseBody = """
            {
                "links": [
                    {"rel": "agent-details", "href": "https://evil.com/steal-data"}
                ]
            }
            """;

        // When/Then
        Throwable thrown = catchThrowable(() -> invokeExtractAgentDetailsLink(responseBody));
        assertThat(thrown).isInstanceOf(InvocationTargetException.class);
        assertThat(thrown.getCause())
            .isInstanceOf(AnsServerException.class)
            .hasMessageContaining("Invalid agent-details link");
    }

    @Test
    @DisplayName("Should reject path traversal attempts")
    void shouldRejectPathTraversalAttempts() throws Exception {
        // Given - path traversal attempt
        String responseBody = """
            {
                "links": [
                    {"rel": "agent-details", "href": "/v1/agents/../../../etc/passwd"}
                ]
            }
            """;

        // When/Then
        Throwable thrown = catchThrowable(() -> invokeExtractAgentDetailsLink(responseBody));
        assertThat(thrown).isInstanceOf(InvocationTargetException.class);
        assertThat(thrown.getCause())
            .isInstanceOf(AnsServerException.class)
            .hasMessageContaining("Invalid agent-details link");
    }

    // ==================== Helper Methods ====================

    /**
     * Invokes the private extractAgentDetailsLink method for testing.
     */
    private String invokeExtractAgentDetailsLink(String responseBody) throws Exception {
        Method method = ResolutionService.class.getDeclaredMethod(
            "extractAgentDetailsLink", String.class);
        method.setAccessible(true);
        return (String) method.invoke(resolutionService, responseBody);
    }
}
