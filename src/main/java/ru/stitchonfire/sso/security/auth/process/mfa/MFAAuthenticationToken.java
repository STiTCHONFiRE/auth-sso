package ru.stitchonfire.sso.security.auth.process.mfa;

import java.util.Objects;
import lombok.Getter;
import org.springframework.security.core.Authentication;
import ru.stitchonfire.sso.security.auth.process.AbstractProcessToken;

public class MFAAuthenticationToken extends AbstractProcessToken {

    @Getter
    private final String code;

    public MFAAuthenticationToken(Object principal, Authentication linkedAuthentication, String code) {
        super(null, principal, linkedAuthentication);
        this.code = code;
        super.setAuthenticated(false); // to be sure that the token is not authenticated
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;
        if (!super.equals(object)) return false;
        MFAAuthenticationToken that = (MFAAuthenticationToken) object;
        return Objects.equals(code, that.code);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), code);
    }
}
