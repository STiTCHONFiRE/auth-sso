package ru.stitchonfire.sso.security.auth.process.face;

import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.web.multipart.MultipartFile;
import ru.stitchonfire.sso.security.auth.process.AbstractProcessToken;

import java.util.Objects;

public class FaceAuthenticationToken extends AbstractProcessToken {

    @Getter
    private final MultipartFile faceFile;

    public FaceAuthenticationToken(Object principal, Authentication linkedAuthentication, MultipartFile file) {
        super(null, principal, linkedAuthentication);
        this.faceFile = file;
        super.setAuthenticated(false);
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;
        if (!super.equals(object)) return false;
        FaceAuthenticationToken that = (FaceAuthenticationToken) object;
        return Objects.equals(faceFile, that.faceFile);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), faceFile);
    }

}
