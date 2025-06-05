package ru.stitchonfire.sso.security.auth.process.totp;

import java.util.Objects;
import lombok.Getter;
import org.springframework.security.core.Authentication;
import ru.stitchonfire.sso.security.auth.process.AbstractProcessToken;

public class TotpAuthenticationToken extends AbstractProcessToken {

    @Getter
    private final String code;

    public TotpAuthenticationToken(Object principal, Authentication linkedAuthentication, String code) {
        super(null, principal, linkedAuthentication);
        this.code = code;
        super.setAuthenticated(false); // to be sure that the token is not authenticated
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;
        if (!super.equals(object)) return false;
        TotpAuthenticationToken that = (TotpAuthenticationToken) object;
        return Objects.equals(code, that.code);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), code);
    }
}
