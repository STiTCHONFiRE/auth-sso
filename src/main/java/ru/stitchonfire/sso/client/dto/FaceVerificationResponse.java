package ru.stitchonfire.sso.client.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record FaceVerificationResponse(
        List<Result> result
) {

    public record Result(
            @JsonProperty("face_matches")
            List<FaceMatches> faceMatches
    ) { }

    public record FaceMatches(
            double similarity
    ) {}
}
