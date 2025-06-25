package ru.stitchonfire.sso.security.auth.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.savedrequest.SavedRequest;
import ru.stitchonfire.sso.security.auth.process.AbstractAuthenticationProcessFilter;

public interface ChainedAuthenticationProcess {

    Class<? extends AbstractAuthenticationProcessFilter> getFilterClass();

    boolean needToProcess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication,
            SavedRequest savedRequest)
            throws ServletException, IOException;

    boolean isTheNext(Authentication authentication);

    String getProcessUri();

    String getProcessQuery(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication,
            SavedRequest savedRequest);
}
