package ru.stitchonfire.sso.security.auth.process.question;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.savedrequest.SavedRequest;
import ru.stitchonfire.sso.security.auth.handler.ChainedAuthenticationProcess;
import ru.stitchonfire.sso.security.auth.process.AbstractAuthenticationProcessFilter;
import ru.stitchonfire.sso.security.auth.process.mfa.MFAAuthenticationToken;

public class QuestionAuthenticationProcess implements ChainedAuthenticationProcess {

    /*
     * This class is an example, if you want more explanation, please refer to the MFAAuthenticationProcess.java
     */

    @Override
    public Class<? extends AbstractAuthenticationProcessFilter> getFilterClass() {
        return QuestionAuthenticationFilter.class;
    }

    @Override
    public boolean needToProcess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication,
            SavedRequest savedRequest)
            throws ServletException, IOException {
        return true;
    }

    @Override
    public boolean isTheNext(Authentication authentication) {
        return authentication instanceof MFAAuthenticationToken;
    }

    @Override
    public String getProcessUri() {
        return "/question";
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
