package ru.stitchonfire.sso.security.auth.process.totp;

import com.bastiaanjansen.otp.HMACAlgorithm;
import com.bastiaanjansen.otp.TOTPGenerator;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base32;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import ru.stitchonfire.sso.security.model.User;

import java.time.Duration;

@Slf4j
public class TotpAuthenticationTokenProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        TotpAuthenticationToken mfaAuthenticationToken = (TotpAuthenticationToken) authentication;

        if (authentication.getPrincipal() instanceof User u) {
            var totpGenerator = new TOTPGenerator.Builder(new Base32().decode(u.getTwoFactorSecretKey()))
                    .withHOTPGenerator(builder -> {
                        builder.withPasswordLength(6);
                        builder.withAlgorithm(HMACAlgorithm.SHA256);
                    })
                    .withPeriod(Duration.ofSeconds(30))
                    .build();

            if (totpGenerator.verify(mfaAuthenticationToken.getCode())) {
                authentication.setAuthenticated(true);
                return authentication;
            }
        }

        throw new BadCredentialsException("Invalid code");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return TotpAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
