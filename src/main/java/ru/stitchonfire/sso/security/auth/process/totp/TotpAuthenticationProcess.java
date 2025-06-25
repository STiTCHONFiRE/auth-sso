package ru.stitchonfire.sso.security.auth.process.totp;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.savedrequest.SavedRequest;
import ru.stitchonfire.sso.security.auth.handler.ChainedAuthenticationProcess;
import ru.stitchonfire.sso.security.auth.process.AbstractAuthenticationProcessFilter;
import ru.stitchonfire.sso.security.auth.provider.NoCompletedAuthenticationToken;
import ru.stitchonfire.sso.security.model.User;

public class TotpAuthenticationProcess implements ChainedAuthenticationProcess {

    @Override
    public Class<? extends AbstractAuthenticationProcessFilter> getFilterClass() {
        return TotpAuthenticationFilter.class;
    }

    @Override
    public boolean needToProcess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication,
            SavedRequest savedRequest)
            throws ServletException, IOException {
        User user = (User) authentication.getPrincipal();
        return user.isAccountNonExpired() && user.isEnabled();
    }

    @Override
    public boolean isTheNext(Authentication authentication) {
        return authentication instanceof NoCompletedAuthenticationToken;
    }

    @Override
    public String getProcessUri() {
        return "/mfa";
    }

    @Override
    public String getProcessQuery(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication,
            SavedRequest savedRequest) {
        return null;
    }
}
