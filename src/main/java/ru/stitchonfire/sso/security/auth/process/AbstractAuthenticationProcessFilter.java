package ru.stitchonfire.sso.security.auth.process;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import ru.stitchonfire.sso.security.auth.handler.ChainedAuthenticationHandler;
import ru.stitchonfire.sso.security.auth.provider.NoCompletedAuthenticationToken;

public abstract class AbstractAuthenticationProcessFilter extends AbstractAuthenticationProcessingFilter {

    protected AbstractAuthenticationProcessFilter(
            RequestMatcher requestMatcher,
            AuthenticationManager authenticationManager,
            ChainedAuthenticationHandler chainedAuthenticationHandler) {
        super(requestMatcher, authenticationManager);
        setAuthenticationSuccessHandler(chainedAuthenticationHandler);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        if (!request.getMethod().equals(getHttpMethod())) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        Authentication currentAuthentication =
                SecurityContextHolder.getContext().getAuthentication();
        if (!(currentAuthentication instanceof NoCompletedAuthenticationToken noCompletedAuthenticationToken)) {
            throw new AuthenticationServiceException("NoCompletedAuthenticationToken is not found");
        }

        if (noCompletedAuthenticationToken.getActualAuthenticationProcess() != getClass()) {
            throw new AuthenticationServiceException(
                    "Actual authentication process is not " + getClass().getSimpleName());
        }

        return authenticationProcess(request, response);
    }

    public abstract Authentication authenticationProcess(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException;

    public abstract String getHttpMethod();
}
