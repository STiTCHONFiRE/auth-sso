package ru.stitchonfire.sso.security.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import ru.stitchonfire.sso.client.FaceVerifierClient;
import ru.stitchonfire.sso.security.auth.process.face.FaceAuthenticationTokenProvider;
import ru.stitchonfire.sso.security.auth.process.totp.TotpAuthenticationTokenProvider;
import ru.stitchonfire.sso.security.auth.process.question.QuestionAuthenticationTokenProvider;
import ru.stitchonfire.sso.security.auth.provider.NoCompletedAuthenticationProvider;
import ru.stitchonfire.sso.security.model.User;
import ru.stitchonfire.sso.security.service.OidcUserInfoService;
import ru.stitchonfire.sso.security.repository.UserRepository;
import ru.stitchonfire.sso.security.service.CustomerUserDetailsService;

import java.util.List;

@Slf4j
@Configuration
public class AuthenticationConfiguration {

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return new CustomerUserDetailsService(userRepository, passwordEncoder);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public NoCompletedAuthenticationProvider customAuthenticationProvider(
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder
    ) {
        NoCompletedAuthenticationProvider provider = new NoCompletedAuthenticationProvider(passwordEncoder);
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(FaceVerifierClient client) {
        return new ProviderManager(
                List.of(
                        new TotpAuthenticationTokenProvider(),
                        new QuestionAuthenticationTokenProvider(),
                        new FaceAuthenticationTokenProvider(client)
                )
        );
    }

//    @Bean
//    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(
//            OidcUserInfoService userInfoService, UserDetailsService userDetailsService) {
//        return (context) -> {
//            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
//                var profileScope = context.getAuthorizedScopes().stream().filter(scope -> scope.equals("profile")).findFirst();
//
//                if (profileScope.isPresent()) {
//                    OidcUserInfo userInfo = userInfoService.loadUser(
//                            context.getPrincipal().getName());
//                    context.getClaims().claims(claims ->
//                            claims.putAll(userInfo.getClaims()));
//                }
//            } else {
//                if (userDetailsService.loadUserByUsername(context.getPrincipal().getName()) instanceof User u) {
//                    context.getClaims().subject(u.getId().toString());
//                }
//
//            }
//        };
//    }
}
