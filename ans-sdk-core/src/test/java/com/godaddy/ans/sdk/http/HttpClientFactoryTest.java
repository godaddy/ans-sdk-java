package com.godaddy.ans.sdk.http;

import com.godaddy.ans.sdk.auth.JwtCredentialsProvider;
import com.godaddy.ans.sdk.config.AnsConfiguration;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for HttpClientFactory.
 */
class HttpClientFactoryTest {

    @Test
    void createWithConfigurationShouldReturnConfiguredClient() {
        AnsConfiguration config = AnsConfiguration.builder()
            .credentialsProvider(new JwtCredentialsProvider("test-token"))
            .connectTimeout(Duration.ofSeconds(30))
            .build();

        HttpClient client = HttpClientFactory.create(config);

        assertThat(client).isNotNull();
        assertThat(client.connectTimeout()).isPresent();
        assertThat(client.connectTimeout().get()).isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    void createDefaultShouldReturnClientWithDefaults() {
        HttpClient client = HttpClientFactory.createDefault();

        assertThat(client).isNotNull();
        assertThat(client.connectTimeout()).isPresent();
        assertThat(client.connectTimeout().get()).isEqualTo(Duration.ofSeconds(10));
    }

    @Test
    void createShouldConfigureRedirectPolicy() {
        AnsConfiguration config = AnsConfiguration.builder()
            .credentialsProvider(new JwtCredentialsProvider("test-token"))
            .build();

        HttpClient client = HttpClientFactory.create(config);

        assertThat(client.followRedirects()).isEqualTo(HttpClient.Redirect.NORMAL);
    }

    @Test
    void createDefaultShouldConfigureRedirectPolicy() {
        HttpClient client = HttpClientFactory.createDefault();

        assertThat(client.followRedirects()).isEqualTo(HttpClient.Redirect.NORMAL);
    }
}
