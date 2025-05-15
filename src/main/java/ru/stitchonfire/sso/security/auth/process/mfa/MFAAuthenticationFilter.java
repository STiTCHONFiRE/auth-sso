package ru.stitchonfire.sso.security.auth.process.mfa;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import ru.stitchonfire.sso.security.auth.handler.ChainedAuthenticationHandler;
import ru.stitchonfire.sso.security.auth.process.AbstractAuthenticationProcessFilter;

public class MFAAuthenticationFilter extends AbstractAuthenticationProcessFilter {

    private static final String MFA_KEY = "mfa_code";
    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER =
            new AntPathRequestMatcher("/mfa", "POST");

    public MFAAuthenticationFilter(
            AuthenticationManager authenticationManager, ChainedAuthenticationHandler chainedAuthenticationHandler) {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager, chainedAuthenticationHandler);

        setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/mfa?error"));
    }

    @Override
    public Authentication authenticationProcess(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        String code = request.getParameter(MFA_KEY);
        if (code == null || code.isEmpty()) {
            throw new AuthenticationServiceException("MFA code is empty");
        }

        Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();

        MFAAuthenticationToken mfaAuthenticationToken =
                new MFAAuthenticationToken(existingAuth.getPrincipal(), existingAuth, code);
        mfaAuthenticationToken.setDetails(this.authenticationDetailsSource.buildDetails(request));

        return this.getAuthenticationManager().authenticate(mfaAuthenticationToken);
    }

    @Override
    public String getHttpMethod() {
        return "POST";
    }
}
