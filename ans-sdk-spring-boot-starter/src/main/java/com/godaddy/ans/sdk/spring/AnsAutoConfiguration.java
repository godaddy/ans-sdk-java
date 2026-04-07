package com.godaddy.ans.sdk.spring;

import com.godaddy.ans.sdk.auth.ApiKeyCredentialsProvider;
import com.godaddy.ans.sdk.auth.AnsCredentialsProvider;
import com.godaddy.ans.sdk.auth.EnvironmentCredentialsProvider;
import com.godaddy.ans.sdk.auth.JwtCredentialsProvider;
import com.godaddy.ans.sdk.config.AnsConfiguration;
import com.godaddy.ans.sdk.discovery.DiscoveryClient;
import com.godaddy.ans.sdk.registration.RegistrationClient;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Spring Boot auto-configuration for ANS SDK.
 *
 * <p>Automatically creates {@link AnsConfiguration}, {@link RegistrationClient},
 * and {@link DiscoveryClient} beans from {@code ans.*} application properties.</p>
 *
 * <p>This auto-configuration is enabled when {@code ans.enabled} is {@code true} (default).</p>
 *
 * <p>All beans are conditional on missing beans, so users can override
 * any bean by defining their own.</p>
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "ans", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(AnsProperties.class)
public class AnsAutoConfiguration {

    /**
     * Creates the credentials provider based on configured credential type.
     *
     * @param properties the ANS properties
     * @return the credentials provider
     */
    @Bean
    @ConditionalOnMissingBean
    public AnsCredentialsProvider ansCredentialsProvider(AnsProperties properties) {
        AnsProperties.Credentials creds = properties.getCredentials();

        if (creds.getType() == null) {
            throw new IllegalStateException(
                "ans.credentials.type is required. Supported values: jwt, api-key, environment");
        }

        switch (creds.getType()) {
            case JWT:
                if (creds.getJwtToken() == null || creds.getJwtToken().isBlank()) {
                    throw new IllegalStateException(
                        "ans.credentials.jwt-token is required when credentials type is jwt");
                }
                return new JwtCredentialsProvider(creds.getJwtToken());

            case API_KEY:
                if (creds.getApiKey() == null || creds.getApiKey().isBlank()) {
                    throw new IllegalStateException(
                        "ans.credentials.api-key is required when credentials type is api-key");
                }
                if (creds.getApiSecret() == null || creds.getApiSecret().isBlank()) {
                    throw new IllegalStateException(
                        "ans.credentials.api-secret is required when credentials type is api-key");
                }
                return new ApiKeyCredentialsProvider(creds.getApiKey(), creds.getApiSecret());

            case ENVIRONMENT:
                return new EnvironmentCredentialsProvider();

            default:
                throw new IllegalStateException("Unsupported credential type: " + creds.getType());
        }
    }

    /**
     * Creates the ANS configuration from properties.
     *
     * @param properties the ANS properties
     * @param credentialsProvider the credentials provider
     * @return the ANS configuration
     */
    @Bean
    @ConditionalOnMissingBean
    public AnsConfiguration ansConfiguration(AnsProperties properties,
                                             AnsCredentialsProvider credentialsProvider) {
        if (properties.getEnvironment() == null) {
            throw new IllegalStateException(
                "ans.environment is required. Supported values: OTE, PROD");
        }

        AnsConfiguration.Builder builder = AnsConfiguration.builder()
            .environment(properties.getEnvironment())
            .credentialsProvider(credentialsProvider);

        if (properties.getBaseUrl() != null) {
            builder.baseUrl(properties.getBaseUrl());
        }
        if (properties.getConnectTimeout() != null) {
            builder.connectTimeout(properties.getConnectTimeout());
        }
        if (properties.getReadTimeout() != null) {
            builder.readTimeout(properties.getReadTimeout());
        }
        if (properties.getMaxRetries() != null) {
            builder.enableRetry(properties.getMaxRetries());
        }

        return builder.build();
    }

    /**
     * Creates a RegistrationClient bean.
     *
     * @param configuration the ANS configuration
     * @return the registration client
     */
    @Bean
    @ConditionalOnMissingBean
    public RegistrationClient registrationClient(AnsConfiguration configuration) {
        return RegistrationClient.builder()
            .configuration(configuration)
            .build();
    }

    /**
     * Creates a DiscoveryClient bean.
     *
     * @param configuration the ANS configuration
     * @return the discovery client
     */
    @Bean
    @ConditionalOnMissingBean
    public DiscoveryClient discoveryClient(AnsConfiguration configuration) {
        return DiscoveryClient.builder()
            .configuration(configuration)
            .build();
    }
}
