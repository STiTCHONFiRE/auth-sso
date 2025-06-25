package ru.stitchonfire.sso.security.auth.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.StringUtils;
import ru.stitchonfire.sso.security.auth.process.AbstractAuthenticationProcessFilter;
import ru.stitchonfire.sso.security.auth.process.AbstractProcessToken;
import ru.stitchonfire.sso.security.auth.provider.NoCompletedAuthenticationToken;

@RequiredArgsConstructor
public class ChainedAuthenticationHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final RequestCache requestCache = new HttpSessionRequestCache();
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    private final List<ChainedAuthenticationProcess> processes;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws ServletException, IOException {
        SavedRequest savedRequest = this.requestCache.getRequest(request, response);

        // Если у пользователя роль ROLE_MFA_UNCONFIGURED, перенаправляем на страницу настройки MFA
        if (authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch("ROLE_MFA_UNCONFIGURED"::equals)) {
            getRedirectStrategy().sendRedirect(request, response, "/setup-mfa");
            return;
        }

        if (savedRequest == null) {
            super.onAuthenticationSuccess(request, response, authentication);
            return;
        }
        String targetUrlParameter = getTargetUrlParameter();
        if (isAlwaysUseDefaultTargetUrl()
                || (targetUrlParameter != null && StringUtils.hasText(request.getParameter(targetUrlParameter)))) {
            this.requestCache.removeRequest(request, response);
            super.onAuthenticationSuccess(request, response, authentication);
            return;
        }
        clearAuthenticationAttributes(request);

        if (!authentication.isAuthenticated() && !(authentication instanceof NoCompletedAuthenticationToken)) {
            throw new AuthenticationServiceException("Authentication token is not authenticated");
        }

        String targetUrl = savedRequest.getRedirectUrl();

        boolean hasNext = false;
        for (ChainedAuthenticationProcess process : processes) {
            if (process.isTheNext(authentication)) {
                if (process.needToProcess(request, response, authentication, savedRequest)) {
                    hasNext = true;
                    targetUrl = buildProcessUri(request, response, authentication, savedRequest, process);
                    updateToNoCompletedToken(authentication, process.getFilterClass());
                }

                break;
            }
        }

        if (!hasNext) {
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(extractOriginalAuthentication(authentication));
            securityContextRepository.saveContext(context, request, response);
        }

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    private String buildProcessUri(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication,
            SavedRequest savedRequest,
            ChainedAuthenticationProcess process) {
        return UrlUtils.buildFullRequestUrl(
                request.getScheme(),
                request.getServerName(),
                request.getServerPort(),
                process.getProcessUri(),
                process.getProcessQuery(request, response, authentication, savedRequest));
    }

    private Authentication extractOriginalAuthentication(Authentication authentication) {
        if (authentication instanceof NoCompletedAuthenticationToken noCompletedAuthenticationToken) {
            return noCompletedAuthenticationToken.getOriginalAuthentication();
        }

        if (authentication instanceof AbstractProcessToken processToken) {
            return extractOriginalAuthentication(processToken.getLinkedAuthentication());
        }

        throw new AuthenticationServiceException(
                "Unable to find the original authentication token (UsernamePasswordAuthenticationToken)");
    }

    private void updateToNoCompletedToken(
            Authentication authentication, Class<? extends AbstractAuthenticationProcessFilter> filterClass) {
        if (authentication instanceof AbstractProcessToken processToken
                && processToken.getLinkedAuthentication()
                        instanceof NoCompletedAuthenticationToken noCompletedAuthenticationToken) {
            noCompletedAuthenticationToken.setActualAuthenticationProcess(filterClass);
        } else {
            throw new AuthenticationServiceException("Unable to find the NoCompletedAuthenticationToken");
        }
    }

}
