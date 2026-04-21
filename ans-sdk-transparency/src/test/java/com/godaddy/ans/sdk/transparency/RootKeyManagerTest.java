package com.godaddy.ans.sdk.transparency;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.github.tomakehurst.wiremock.stubbing.Scenario;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.security.PublicKey;
import java.time.Duration;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@WireMockTest
class RootKeyManagerTest {

    private static final String TEST_EC_PUBLIC_KEY =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEveuRZW0vWcVjh4enr9tA7VAKPFmL"
            + "OZs1S99lGDqRhAQBEdetB290Det8rO1ojnHEA8PX4Yojb0oomwA2krO5Ag==";

    private static final String VALID_ROOT_KEY_RESPONSE =
        "transparency.ans.godaddy.com+abcd1234+" + TEST_EC_PUBLIC_KEY;

    @Test
    @DisplayName("should retry and succeed after transient failure")
    void shouldRetryOnTransientFailure(WireMockRuntimeInfo wmInfo) {
        // First request fails, second succeeds
        stubFor(get(urlEqualTo("/root-keys"))
            .inScenario("retry")
            .whenScenarioStateIs(Scenario.STARTED)
            .willReturn(aResponse().withStatus(503))
            .willSetStateTo("first-failed"));

        stubFor(get(urlEqualTo("/root-keys"))
            .inScenario("retry")
            .whenScenarioStateIs("first-failed")
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "text/plain")
                .withBody(VALID_ROOT_KEY_RESPONSE)));

        HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

        RootKeyManager manager = new RootKeyManager(
            httpClient,
            wmInfo.getHttpBaseUrl(),
            Duration.ofSeconds(5),
            Duration.ofMinutes(5));

        // getRootKeysAsync triggers fetchRootKeysFromServerAsync via Caffeine
        // The first attempt fails with 503, retry should succeed with empty keys
        Map<String, PublicKey> keys = manager.getRootKeysAsync().join();
        assertThat(keys).isNotNull();

        // Verify two requests were made (initial + 1 retry)
        verify(2, getRequestedFor(urlEqualTo("/root-keys")));
    }

    @Test
    @DisplayName("should fail after exhausting all retries")
    void shouldFailAfterMaxRetries(WireMockRuntimeInfo wmInfo) {
        // All requests fail
        stubFor(get(urlEqualTo("/root-keys"))
            .willReturn(aResponse().withStatus(503)));

        HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

        RootKeyManager manager = new RootKeyManager(
            httpClient,
            wmInfo.getHttpBaseUrl(),
            Duration.ofSeconds(5),
            Duration.ofMinutes(5));

        assertThatThrownBy(() -> manager.getRootKeysAsync().join())
            .hasCauseInstanceOf(com.godaddy.ans.sdk.exception.AnsServerException.class);

        // Verify 3 requests were made (initial + 2 retries)
        verify(3, getRequestedFor(urlEqualTo("/root-keys")));
    }
}
