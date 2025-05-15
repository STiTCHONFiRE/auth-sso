package ru.stitchonfire.sso.security.auth.process.mfa;

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

public class MFAAuthenticationProcess implements ChainedAuthenticationProcess {

    @Override
    public Class<? extends AbstractAuthenticationProcessFilter> getFilterClass() {
        return MFAAuthenticationFilter.class;
    }

    @Override
    public boolean needToProcess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication,
            SavedRequest savedRequest)
            throws ServletException, IOException {
        // Here is an example, you can implement your own logic
        User user = (User) authentication.getPrincipal();
        return user.isAccountNonExpired() && user.isEnabled();
    }

    @Override
    public boolean isTheNext(Authentication authentication) {
        /*
        This method determines whether MFAAuthenticationProcess should be launched or not. This method manages the chain mechanics.
        NoCompletedAuthenticationToken is the token returned by the login operation.
        So this process will be executed just after /login. If we wanted this process to be executed after another,
        we would have had to set the token of that process (e.g. in QuestionAuthenticationProcess).
         */
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
