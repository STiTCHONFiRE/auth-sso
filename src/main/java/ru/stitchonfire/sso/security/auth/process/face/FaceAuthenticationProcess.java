package ru.stitchonfire.sso.security.auth.process.face;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.savedrequest.SavedRequest;
import ru.stitchonfire.sso.security.auth.handler.ChainedAuthenticationProcess;
import ru.stitchonfire.sso.security.auth.process.AbstractAuthenticationProcessFilter;
import ru.stitchonfire.sso.security.auth.process.question.QuestionAuthenticationToken;

import java.io.IOException;

public class FaceAuthenticationProcess implements ChainedAuthenticationProcess {

    @Override
    public Class<? extends AbstractAuthenticationProcessFilter> getFilterClass() {
        return FaceAuthenticationFilter.class;
    }

    @Override
    public boolean needToProcess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication,
            SavedRequest savedRequest
    ) throws ServletException, IOException {
        return true;
    }

    @Override
    public boolean isTheNext(Authentication authentication) {
        return authentication instanceof QuestionAuthenticationToken;
    }

    @Override
    public String getProcessUri() {
        return "/face";
    }

    @Override
    public String getProcessQuery(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication,
            SavedRequest savedRequest
    ) {
        return null;
    }

}
