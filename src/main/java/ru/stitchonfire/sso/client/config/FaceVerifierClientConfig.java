package ru.stitchonfire.sso.client.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import java.time.Duration;

@Configuration
public class FaceVerifierClientConfig {

    @Value("${compreface.base-url}")
    String url;

    @Value("${compreface.api-key}")
    String apiKey;

    @Bean
    public RestClient comprefaceRestClient() {
        return RestClient.builder()
                .baseUrl(url)
                .defaultHeader("x-api-key", apiKey)
                .build();
    }
}
