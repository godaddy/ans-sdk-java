package com.godaddy.ans.examples.a2a;

import io.a2a.client.http.A2AHttpClient;
import io.a2a.client.http.A2AHttpResponse;
import io.a2a.common.A2AErrorMessages;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.net.http.HttpResponse.BodyHandlers;
import java.net.http.HttpResponse.BodySubscribers;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Flow;
import java.util.function.Consumer;

import static java.net.HttpURLConnection.HTTP_FORBIDDEN;
import static java.net.HttpURLConnection.HTTP_MULT_CHOICE;
import static java.net.HttpURLConnection.HTTP_OK;
import static java.net.HttpURLConnection.HTTP_UNAUTHORIZED;

/**
 * A2A HTTP client adapter with custom SSLContext support for ANS certificate capture.
 *
 * <p>This adapter implements the A2A SDK's {@link A2AHttpClient} interface and allows
 * injecting a custom {@link SSLContext} for ANS verification. The A2A SDK's built-in
 * {@code JdkA2AHttpClient} doesn't expose SSL customization, so this adapter provides
 * that capability.</p>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * SSLContext sslContext = AnsVerifiedSslContextFactory.create();
 * HttpClientA2AAdapter httpClient = new HttpClientA2AAdapter(sslContext);
 *
 * // Use with A2A client
 * A2ACardResolver cardResolver = new A2ACardResolver(httpClient, serverUrl, null);
 * AgentCard card = cardResolver.getAgentCard();
 *
 * JSONRPCTransportConfig config = new JSONRPCTransportConfig(httpClient);
 * Client client = Client.builder(card)
 *     .withTransport(JSONRPCTransport.class, config)
 *     .build();
 * }</pre>
 *
 * @see com.godaddy.ans.sdk.agent.http.AnsVerifiedSslContextFactory
 * @see com.godaddy.ans.sdk.agent.http.CertificateCapturingTrustManager
 */
public class HttpClientA2AAdapter implements A2AHttpClient {

    private final HttpClient httpClient;

    /**
     * Creates an A2A HTTP client adapter with a custom SSLContext.
     *
     * @param sslContext the SSLContext to use for TLS connections
     */
    public HttpClientA2AAdapter(SSLContext sslContext) {
        this.httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_2)
            .followRedirects(HttpClient.Redirect.NORMAL)
            .sslContext(sslContext)
            .build();
    }

    @Override
    public GetBuilder createGet() {
        return new AdapterGetBuilder();
    }

    @Override
    public PostBuilder createPost() {
        return new AdapterPostBuilder();
    }

    @Override
    public DeleteBuilder createDelete() {
        return new AdapterDeleteBuilder();
    }

    private abstract class AdapterBuilder<T extends Builder<T>> implements Builder<T> {
        private String url = "";
        private final Map<String, String> headers = new HashMap<>();

        @Override
        public T url(String url) {
            this.url = url;
            return self();
        }

        @Override
        public T addHeader(String name, String value) {
            headers.put(name, value);
            return self();
        }

        @Override
        public T addHeaders(Map<String, String> headers) {
            if (headers != null && !headers.isEmpty()) {
                for (Map.Entry<String, String> entry : headers.entrySet()) {
                    addHeader(entry.getKey(), entry.getValue());
                }
            }
            return self();
        }

        @SuppressWarnings("unchecked")
        T self() {
            return (T) this;
        }

        protected HttpRequest.Builder createRequestBuilder() {
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url));
            for (Map.Entry<String, String> headerEntry : headers.entrySet()) {
                builder.header(headerEntry.getKey(), headerEntry.getValue());
            }
            return builder;
        }

        protected CompletableFuture<Void> asyncRequest(
                HttpRequest request,
                Consumer<String> messageConsumer,
                Consumer<Throwable> errorConsumer,
                Runnable completeRunnable) {

            Flow.Subscriber<String> subscriber = new Flow.Subscriber<>() {
                private Flow.Subscription subscription;
                private volatile boolean errorRaised = false;

                @Override
                public void onSubscribe(Flow.Subscription subscription) {
                    this.subscription = subscription;
                    this.subscription.request(1);
                }

                @Override
                public void onNext(String item) {
                    // SSE messages sometimes start with "data:". Strip that off
                    if (item != null && item.startsWith("data:")) {
                        item = item.substring(5).trim();
                        if (!item.isEmpty()) {
                            messageConsumer.accept(item);
                        }
                    }
                    if (subscription != null) {
                        subscription.request(1);
                    }
                }

                @Override
                public void onError(Throwable throwable) {
                    if (!errorRaised) {
                        errorRaised = true;
                        errorConsumer.accept(throwable);
                    }
                    if (subscription != null) {
                        subscription.cancel();
                    }
                }

                @Override
                public void onComplete() {
                    if (!errorRaised) {
                        completeRunnable.run();
                    }
                    if (subscription != null) {
                        subscription.cancel();
                    }
                }
            };

            BodyHandler<Void> bodyHandler = responseInfo -> {
                if (responseInfo.statusCode() == HTTP_UNAUTHORIZED
                        || responseInfo.statusCode() == HTTP_FORBIDDEN) {
                    final String errorMessage;
                    if (responseInfo.statusCode() == HTTP_UNAUTHORIZED) {
                        errorMessage = A2AErrorMessages.AUTHENTICATION_FAILED;
                    } else {
                        errorMessage = A2AErrorMessages.AUTHORIZATION_FAILED;
                    }
                    return BodySubscribers.fromSubscriber(new Flow.Subscriber<List<ByteBuffer>>() {
                        @Override
                        public void onSubscribe(Flow.Subscription subscription) {
                            subscriber.onError(new IOException(errorMessage));
                        }

                        @Override
                        public void onNext(List<ByteBuffer> item) {}

                        @Override
                        public void onError(Throwable throwable) {}

                        @Override
                        public void onComplete() {}
                    });
                } else {
                    return BodyHandlers.fromLineSubscriber(subscriber).apply(responseInfo);
                }
            };

            return httpClient.sendAsync(request, bodyHandler)
                .thenAccept(response -> {
                    if (!isSuccessStatus(response.statusCode())
                            && response.statusCode() != HTTP_UNAUTHORIZED
                            && response.statusCode() != HTTP_FORBIDDEN) {
                        subscriber.onError(new IOException(
                            "Request failed with status " + response.statusCode()
                                + ":" + response.body()));
                    }
                });
        }
    }

    private class AdapterGetBuilder extends AdapterBuilder<GetBuilder> implements GetBuilder {

        private HttpRequest.Builder createRequestBuilder(boolean sse) {
            HttpRequest.Builder builder = super.createRequestBuilder().GET();
            if (sse) {
                builder.header(ACCEPT, EVENT_STREAM);
            }
            return builder;
        }

        @Override
        public A2AHttpResponse get() throws IOException, InterruptedException {
            HttpRequest request = createRequestBuilder(false).build();
            HttpResponse<String> response =
                httpClient.send(request, BodyHandlers.ofString(StandardCharsets.UTF_8));
            return new AdapterHttpResponse(response);
        }

        @Override
        public CompletableFuture<Void> getAsyncSSE(
                Consumer<String> messageConsumer,
                Consumer<Throwable> errorConsumer,
                Runnable completeRunnable) throws IOException, InterruptedException {
            HttpRequest request = createRequestBuilder(true).build();
            return super.asyncRequest(request, messageConsumer, errorConsumer, completeRunnable);
        }
    }

    private class AdapterDeleteBuilder extends AdapterBuilder<DeleteBuilder> implements DeleteBuilder {

        @Override
        public A2AHttpResponse delete() throws IOException, InterruptedException {
            HttpRequest request = super.createRequestBuilder().DELETE().build();
            HttpResponse<String> response =
                httpClient.send(request, BodyHandlers.ofString(StandardCharsets.UTF_8));
            return new AdapterHttpResponse(response);
        }
    }

    private class AdapterPostBuilder extends AdapterBuilder<PostBuilder> implements PostBuilder {
        private String body = "";

        @Override
        public PostBuilder body(String body) {
            this.body = body;
            return self();
        }

        private HttpRequest.Builder createRequestBuilder(boolean sse) {
            HttpRequest.Builder builder = super.createRequestBuilder()
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
            if (sse) {
                builder.header(ACCEPT, EVENT_STREAM);
            }
            return builder;
        }

        @Override
        public A2AHttpResponse post() throws IOException, InterruptedException {
            HttpRequest request = createRequestBuilder(false)
                .build();
            HttpResponse<String> response =
                httpClient.send(request, BodyHandlers.ofString(StandardCharsets.UTF_8));

            if (response.statusCode() == HTTP_UNAUTHORIZED) {
                throw new IOException(A2AErrorMessages.AUTHENTICATION_FAILED);
            } else if (response.statusCode() == HTTP_FORBIDDEN) {
                throw new IOException(A2AErrorMessages.AUTHORIZATION_FAILED);
            }

            return new AdapterHttpResponse(response);
        }

        @Override
        public CompletableFuture<Void> postAsyncSSE(
                Consumer<String> messageConsumer,
                Consumer<Throwable> errorConsumer,
                Runnable completeRunnable) throws IOException, InterruptedException {
            HttpRequest request = createRequestBuilder(true).build();
            return super.asyncRequest(request, messageConsumer, errorConsumer, completeRunnable);
        }
    }

    private record AdapterHttpResponse(HttpResponse<String> response) implements A2AHttpResponse {

        @Override
        public int status() {
            return response.statusCode();
        }

        @Override
        public boolean success() {
            return response.statusCode() >= HTTP_OK && response.statusCode() < HTTP_MULT_CHOICE;
        }

        @Override
        public String body() {
            return response.body();
        }
    }

    private static boolean isSuccessStatus(int statusCode) {
        return statusCode >= HTTP_OK && statusCode < HTTP_MULT_CHOICE;
    }
}