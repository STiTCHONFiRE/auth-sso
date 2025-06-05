package ru.stitchonfire.sso.security.auth.process.face;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import ru.stitchonfire.sso.client.FaceVerifierClient;
import ru.stitchonfire.sso.security.model.User;

import java.io.IOException;
import java.util.Base64;

@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class FaceAuthenticationTokenProvider implements AuthenticationProvider {

    FaceVerifierClient faceVerifierClient;

    @Override
    public Authentication authenticate(Authentication authentication) {
        FaceAuthenticationToken faceAuthentication = (FaceAuthenticationToken) authentication;

        try {
            String source = ((User) faceAuthentication.getPrincipal()).getEncodedFace();
            String target = Base64.getEncoder().encodeToString(faceAuthentication.getFaceFile().getBytes());

            var res = faceVerifierClient.verifyFace(target, source);
            var faceMatches = res.result().getFirst().faceMatches().getFirst();
            if (faceMatches.similarity() > 0.95) {
                authentication.setAuthenticated(true);
                return authentication;
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        throw new BadCredentialsException("Face authentication failed");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return FaceAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
