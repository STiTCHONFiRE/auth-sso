package ru.stitchonfire.sso.security.config;

import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.stitchonfire.sso.security.auth.process.mfa.MFAAuthenticationTokenProvider;
import ru.stitchonfire.sso.security.auth.process.question.QuestionAuthenticationTokenProvider;
import ru.stitchonfire.sso.security.auth.provider.NoCompletedAuthenticationProvider;
import ru.stitchonfire.sso.security.service.CustomerUserDetailsService;

@Configuration
public class AuthenticationConfiguration {

    @Bean
    public UserDetailsService userDetailsService() {
        return new CustomerUserDetailsService();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public NoCompletedAuthenticationProvider customAuthenticationProvider(
            UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        // here, we override the default DaoAuthenticationProvider to return a NoCompletedAuthenticationToken
        NoCompletedAuthenticationProvider provider = new NoCompletedAuthenticationProvider(passwordEncoder);
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        // the authentication manager is the core of the chained authentication process, it will be only use in that
        // context.
        return new ProviderManager(
                List.of(new MFAAuthenticationTokenProvider(), new QuestionAuthenticationTokenProvider()));
    }
}
