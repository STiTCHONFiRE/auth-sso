package ru.stitchonfire.sso.security.auth.process.question;

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

public class QuestionAuthenticationFilter extends AbstractAuthenticationProcessFilter {

    private static final String ANSWER_KEY = "answer";
    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER =
            new AntPathRequestMatcher("/question", "POST");

    public QuestionAuthenticationFilter(
            AuthenticationManager authenticationManager, ChainedAuthenticationHandler chainedAuthenticationHandler) {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager, chainedAuthenticationHandler);

        setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/question?error"));
    }

    @Override
    public Authentication authenticationProcess(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        String answer = request.getParameter(ANSWER_KEY);
        if (answer == null || answer.isEmpty()) {
            throw new AuthenticationServiceException("Answer is empty");
        }

        Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();

        QuestionAuthenticationToken mfaAuthenticationToken =
                new QuestionAuthenticationToken(existingAuth.getPrincipal(), existingAuth, answer);
        mfaAuthenticationToken.setDetails(this.authenticationDetailsSource.buildDetails(request));

        return this.getAuthenticationManager().authenticate(mfaAuthenticationToken);
    }

    @Override
    public String getHttpMethod() {
        return "POST";
    }
}
