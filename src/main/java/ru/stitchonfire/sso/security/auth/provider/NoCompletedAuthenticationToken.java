package ru.stitchonfire.sso.security.auth.provider;

import java.util.List;
import java.util.Objects;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import ru.stitchonfire.sso.security.auth.process.AbstractAuthenticationProcessFilter;
import ru.stitchonfire.sso.security.auth.process.AbstractProcessToken;

public class NoCompletedAuthenticationToken extends AbstractProcessToken {

    @Getter
    @Setter
    private Class<? extends AbstractAuthenticationProcessFilter> actualAuthenticationProcess;

    @Getter
    private final UsernamePasswordAuthenticationToken originalAuthentication;

    public NoCompletedAuthenticationToken(
            Object principal, UsernamePasswordAuthenticationToken originalAuthentication) {
        super(List.of(new SimpleGrantedAuthority("ROLE_NO_COMPLETE_AUTH")), principal, null);
        this.originalAuthentication = originalAuthentication;
        super.setAuthenticated(false);
    }

    @Override
    public Authentication getLinkedAuthentication() {
        return this;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;
        if (!super.equals(object)) return false;
        NoCompletedAuthenticationToken that = (NoCompletedAuthenticationToken) object;
        return Objects.equals(actualAuthenticationProcess, that.actualAuthenticationProcess)
                && Objects.equals(originalAuthentication, that.originalAuthentication);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), actualAuthenticationProcess, originalAuthentication);
    }
}
