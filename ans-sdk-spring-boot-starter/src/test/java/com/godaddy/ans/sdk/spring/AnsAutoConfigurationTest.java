package com.godaddy.ans.sdk.spring;

import com.godaddy.ans.sdk.auth.AnsCredentialsProvider;
import com.godaddy.ans.sdk.auth.ApiKeyCredentialsProvider;
import com.godaddy.ans.sdk.auth.JwtCredentialsProvider;
import com.godaddy.ans.sdk.config.AnsConfiguration;
import com.godaddy.ans.sdk.config.Environment;
import com.godaddy.ans.sdk.discovery.DiscoveryClient;
import com.godaddy.ans.sdk.registration.RegistrationClient;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link AnsAutoConfiguration}.
 */
class AnsAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(AnsAutoConfiguration.class));

    // ==================== API Key Credentials Tests ====================

    @Nested
    @DisplayName("API Key credentials")
    class ApiKeyCredentialsTests {

        @Test
        @DisplayName("Should create all beans with api-key credentials")
        void shouldCreateAllBeansWithApiKeyCredentials() {
            contextRunner
                .withPropertyValues(
                    "ans.environment=OTE",
                    "ans.credentials.type=api-key",
                    "ans.credentials.api-key=my-key",
                    "ans.credentials.api-secret=my-secret"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(AnsCredentialsProvider.class);
                    assertThat(context).hasSingleBean(AnsConfiguration.class);
                    assertThat(context).hasSingleBean(RegistrationClient.class);
                    assertThat(context).hasSingleBean(DiscoveryClient.class);

                    AnsCredentialsProvider provider = context.getBean(AnsCredentialsProvider.class);
                    assertThat(provider).isInstanceOf(ApiKeyCredentialsProvider.class);

                    AnsConfiguration config = context.getBean(AnsConfiguration.class);
                    assertThat(config.getEnvironment()).isEqualTo(Environment.OTE);
                });
        }

        @Test
        @DisplayName("Should fail when api-key is missing")
        void shouldFailWhenApiKeyMissing() {
            contextRunner
                .withPropertyValues(
                    "ans.environment=OTE",
                    "ans.credentials.type=api-key",
                    "ans.credentials.api-secret=my-secret"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                        .rootCause()
                        .hasMessageContaining("ans.credentials.api-key is required");
                });
        }

        @Test
        @DisplayName("Should fail when api-secret is missing")
        void shouldFailWhenApiSecretMissing() {
            contextRunner
                .withPropertyValues(
                    "ans.environment=OTE",
                    "ans.credentials.type=api-key",
                    "ans.credentials.api-key=my-key"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                        .rootCause()
                        .hasMessageContaining("ans.credentials.api-secret is required");
                });
        }
    }

    // ==================== JWT Credentials Tests ====================

    @Nested
    @DisplayName("JWT credentials")
    class JwtCredentialsTests {

        @Test
        @DisplayName("Should create beans with jwt credentials")
        void shouldCreateBeansWithJwtCredentials() {
            contextRunner
                .withPropertyValues(
                    "ans.environment=PROD",
                    "ans.credentials.type=jwt",
                    "ans.credentials.jwt-token=my-jwt-token"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(AnsCredentialsProvider.class);
                    assertThat(context).hasSingleBean(AnsConfiguration.class);

                    AnsCredentialsProvider provider = context.getBean(AnsCredentialsProvider.class);
                    assertThat(provider).isInstanceOf(JwtCredentialsProvider.class);

                    AnsConfiguration config = context.getBean(AnsConfiguration.class);
                    assertThat(config.getEnvironment()).isEqualTo(Environment.PROD);
                });
        }

        @Test
        @DisplayName("Should fail when jwt-token is missing")
        void shouldFailWhenJwtTokenMissing() {
            contextRunner
                .withPropertyValues(
                    "ans.environment=OTE",
                    "ans.credentials.type=jwt"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                        .rootCause()
                        .hasMessageContaining("ans.credentials.jwt-token is required");
                });
        }
    }

    // ==================== Configuration Properties Tests ====================

    @Nested
    @DisplayName("Configuration properties")
    class ConfigurationPropertiesTests {

        @Test
        @DisplayName("Should apply custom timeouts and retries")
        void shouldApplyCustomTimeoutsAndRetries() {
            contextRunner
                .withPropertyValues(
                    "ans.environment=OTE",
                    "ans.credentials.type=api-key",
                    "ans.credentials.api-key=my-key",
                    "ans.credentials.api-secret=my-secret",
                    "ans.connect-timeout=15s",
                    "ans.read-timeout=45s",
                    "ans.max-retries=5"
                )
                .run(context -> {
                    AnsConfiguration config = context.getBean(AnsConfiguration.class);
                    assertThat(config.getConnectTimeout()).isEqualTo(Duration.ofSeconds(15));
                    assertThat(config.getReadTimeout()).isEqualTo(Duration.ofSeconds(45));
                    assertThat(config.getMaxRetries()).isEqualTo(5);
                });
        }

        @Test
        @DisplayName("Should use SDK defaults when timeouts not set")
        void shouldUseSdkDefaultsWhenTimeoutsNotSet() {
            contextRunner
                .withPropertyValues(
                    "ans.environment=OTE",
                    "ans.credentials.type=api-key",
                    "ans.credentials.api-key=my-key",
                    "ans.credentials.api-secret=my-secret"
                )
                .run(context -> {
                    AnsConfiguration config = context.getBean(AnsConfiguration.class);
                    assertThat(config.getConnectTimeout()).isEqualTo(Duration.ofSeconds(10));
                    assertThat(config.getReadTimeout()).isEqualTo(Duration.ofSeconds(30));
                    assertThat(config.getMaxRetries()).isEqualTo(3);
                });
        }

        @Test
        @DisplayName("Should apply custom base URL")
        void shouldApplyCustomBaseUrl() {
            contextRunner
                .withPropertyValues(
                    "ans.environment=OTE",
                    "ans.base-url=https://custom-api.example.com",
                    "ans.credentials.type=api-key",
                    "ans.credentials.api-key=my-key",
                    "ans.credentials.api-secret=my-secret"
                )
                .run(context -> {
                    AnsConfiguration config = context.getBean(AnsConfiguration.class);
                    assertThat(config.getBaseUrl()).isEqualTo("https://custom-api.example.com");
                });
        }
    }

    // ==================== Validation Tests ====================

    @Nested
    @DisplayName("Validation")
    class ValidationTests {

        @Test
        @DisplayName("Should fail when credentials type is missing")
        void shouldFailWhenCredentialsTypeMissing() {
            contextRunner
                .withPropertyValues(
                    "ans.environment=OTE"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                        .rootCause()
                        .hasMessageContaining("ans.credentials.type is required");
                });
        }

        @Test
        @DisplayName("Should fail when environment is missing")
        void shouldFailWhenEnvironmentMissing() {
            contextRunner
                .withPropertyValues(
                    "ans.credentials.type=api-key",
                    "ans.credentials.api-key=my-key",
                    "ans.credentials.api-secret=my-secret"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                        .rootCause()
                        .hasMessageContaining("ans.environment is required");
                });
        }
    }

    // ==================== Conditional Tests ====================

    @Nested
    @DisplayName("Conditional behavior")
    class ConditionalTests {

        @Test
        @DisplayName("Should not create beans when disabled")
        void shouldNotCreateBeansWhenDisabled() {
            contextRunner
                .withPropertyValues("ans.enabled=false")
                .run(context -> {
                    assertThat(context).doesNotHaveBean(AnsConfiguration.class);
                    assertThat(context).doesNotHaveBean(RegistrationClient.class);
                    assertThat(context).doesNotHaveBean(DiscoveryClient.class);
                });
        }

        @Test
        @DisplayName("Should back off when user provides custom AnsConfiguration bean")
        void shouldBackOffWhenUserProvidesCustomConfiguration() {
            contextRunner
                .withPropertyValues(
                    "ans.environment=OTE",
                    "ans.credentials.type=api-key",
                    "ans.credentials.api-key=my-key",
                    "ans.credentials.api-secret=my-secret"
                )
                .withUserConfiguration(CustomConfigurationConfig.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(AnsConfiguration.class);
                    AnsConfiguration config = context.getBean(AnsConfiguration.class);
                    assertThat(config.getBaseUrl()).isEqualTo("https://custom-override.example.com");
                });
        }

        @Test
        @DisplayName("Should back off when user provides custom credentials provider")
        void shouldBackOffWhenUserProvidesCustomCredentialsProvider() {
            contextRunner
                .withPropertyValues(
                    "ans.environment=OTE",
                    "ans.credentials.type=api-key",
                    "ans.credentials.api-key=my-key",
                    "ans.credentials.api-secret=my-secret"
                )
                .withUserConfiguration(CustomCredentialsConfig.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(AnsCredentialsProvider.class);
                    AnsCredentialsProvider provider = context.getBean(AnsCredentialsProvider.class);
                    assertThat(provider).isInstanceOf(JwtCredentialsProvider.class);
                });
        }
    }

    // ==================== User Override Configurations ====================

    @Configuration(proxyBeanMethods = false)
    static class CustomConfigurationConfig {

        @Bean
        AnsConfiguration ansConfiguration() {
            return AnsConfiguration.builder()
                .environment(Environment.PROD)
                .baseUrl("https://custom-override.example.com")
                .credentialsProvider(new JwtCredentialsProvider("custom-token"))
                .build();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomCredentialsConfig {

        @Bean
        AnsCredentialsProvider ansCredentialsProvider() {
            return new JwtCredentialsProvider("overridden-token");
        }
    }
}
