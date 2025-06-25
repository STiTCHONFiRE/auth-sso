package ru.stitchonfire.sso.security.auth.process.face;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.support.StandardServletMultipartResolver;
import ru.stitchonfire.sso.security.auth.handler.ChainedAuthenticationHandler;
import ru.stitchonfire.sso.security.auth.process.AbstractAuthenticationProcessFilter;

public class FaceAuthenticationFilter extends AbstractAuthenticationProcessFilter {

    private static final String FILE_KEY = "face";
    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER =
            new AntPathRequestMatcher("/face", "POST");
    private final StandardServletMultipartResolver multipartResolver =
            new StandardServletMultipartResolver();

    public FaceAuthenticationFilter(
            AuthenticationManager authenticationManager,
            ChainedAuthenticationHandler chainedAuthenticationHandler
    ) {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager, chainedAuthenticationHandler);

        setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/face?error"));
    }

    @Override
    public Authentication authenticationProcess(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (multipartResolver.isMultipart(request)) {
            var multipartReq = multipartResolver.resolveMultipart(request);

            MultipartFile file = multipartReq.getFile(FILE_KEY);

            if (file == null || file.isEmpty()) {
                throw new AuthenticationServiceException("File not found or empty");
            }

            Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();

            FaceAuthenticationToken faceAuthenticationToken =
                    new FaceAuthenticationToken(existingAuth.getPrincipal(), existingAuth, file);
            faceAuthenticationToken.setDetails(this.authenticationDetailsSource.buildDetails(request));

            return this.getAuthenticationManager().authenticate(faceAuthenticationToken);
        }

        throw new AuthenticationServiceException("Unsupported request type");
    }

    @Override
    public String getHttpMethod() {
        return "POST";
    }

}
