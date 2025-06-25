package ru.stitchonfire.sso.security.auth.provider;

import lombok.AllArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;

@AllArgsConstructor
public class NoCompletedAuthenticationProvider extends DaoAuthenticationProvider {

    public NoCompletedAuthenticationProvider(PasswordEncoder passwordEncoder) {
        super(passwordEncoder);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Authentication returnAuthentication = super.authenticate(authentication);
        return new NoCompletedAuthenticationToken(
                returnAuthentication.getPrincipal(), (UsernamePasswordAuthenticationToken) returnAuthentication);
    }
}
