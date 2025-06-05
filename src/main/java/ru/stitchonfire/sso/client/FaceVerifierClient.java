package ru.stitchonfire.sso.client;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import ru.stitchonfire.sso.client.dto.FaceVerificationRequest;
import ru.stitchonfire.sso.client.dto.FaceVerificationResponse;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class FaceVerifierClient {

    RestClient restClient;

    public FaceVerificationResponse verifyFace(String base64Source, String base64Target) {
        FaceVerificationRequest body = new FaceVerificationRequest(base64Source, base64Target, 1);

        return restClient
                .post()
                .uri("/api/v1/verification/verify")
                .body(body)
                .retrieve()
                .body(FaceVerificationResponse.class);
    }
}
