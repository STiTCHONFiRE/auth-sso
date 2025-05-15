package ru.stitchonfire.sso.security.auth.process.mfa;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationStartedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.text.DecimalFormat;
import java.util.Random;

@Slf4j
public class MFAAuthenticationTokenProvider implements AuthenticationProvider {

    String code;

    public MFAAuthenticationTokenProvider() {
        this.generateCode();
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        MFAAuthenticationToken mfaAuthenticationToken = (MFAAuthenticationToken) authentication;

        // Check if the code is correct
        if (code.equals(mfaAuthenticationToken.getCode())) {
            authentication.setAuthenticated(true);
            return authentication;
        }

        throw new BadCredentialsException("Invalid code");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return MFAAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public void generateCode() {
        Random r = new Random();
        int code = r.nextInt(999999);
        DecimalFormat dc = new DecimalFormat("000000");
        this.code = dc.format(code);
        log.info("Generated MFA code: {}", this.code);
    }

}
