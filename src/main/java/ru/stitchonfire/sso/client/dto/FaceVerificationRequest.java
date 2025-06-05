package ru.stitchonfire.sso.client.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record FaceVerificationRequest(
        @JsonProperty("source_image") String source,
        @JsonProperty("target_image") String target,
        @JsonProperty("limit") int limit
) {}
