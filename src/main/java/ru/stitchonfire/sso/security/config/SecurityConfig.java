package ru.stitchonfire.sso.security.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import ru.stitchonfire.sso.security.auth.handler.ChainedAuthenticationHandler;
import ru.stitchonfire.sso.security.auth.handler.ChainedAuthenticationProcess;
import ru.stitchonfire.sso.security.auth.process.AntiExploitAuthenticationProcessFilter;
import ru.stitchonfire.sso.security.auth.process.face.FaceAuthenticationFilter;
import ru.stitchonfire.sso.security.auth.process.face.FaceAuthenticationProcess;
import ru.stitchonfire.sso.security.auth.process.question.QuestionAuthenticationFilter;
import ru.stitchonfire.sso.security.auth.process.question.QuestionAuthenticationProcess;
import ru.stitchonfire.sso.security.auth.process.totp.TotpAuthenticationFilter;
import ru.stitchonfire.sso.security.auth.process.totp.TotpAuthenticationProcess;
import ru.stitchonfire.sso.security.handler.CustomDeniedHandlerHandler;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .cors(Customizer.withDefaults())
                .with(authorizationServerConfigurer, (authorizationServer) ->
                        authorizationServer
                                .oidc(Customizer.withDefaults())
                )
                .authorizeHttpRequests((authorize) ->
                        authorize
                                .anyRequest().authenticated()
                )
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                        .accessDeniedHandler(new CustomDeniedHandlerHandler())
                );

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(
            HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        List<ChainedAuthenticationProcess> processes =
                List.of(new TotpAuthenticationProcess(), new QuestionAuthenticationProcess(), new FaceAuthenticationProcess());
        ChainedAuthenticationHandler chainedAuthenticationHandler = new ChainedAuthenticationHandler(processes);

        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/setup-mfa") // Новая страница для настройки MFA
                        .hasRole("MFA_UNCONFIGURED")
                        .requestMatchers("/mfa", "/question", "/face")
                        .hasRole("NO_COMPLETE_AUTH")
                        .requestMatchers("/registration")
                        .permitAll()
                        .anyRequest()
                        .authenticated())

                .cors(Customizer.withDefaults())
                .csrf(Customizer.withDefaults())
                .formLogin(config -> config.successHandler(chainedAuthenticationHandler).loginPage("/login").permitAll())
                .addFilterBefore(
                        new AntiExploitAuthenticationProcessFilter(processes),
                        UsernamePasswordAuthenticationFilter.class)

                // All process filter here
                .addFilterAfter(
                        new TotpAuthenticationFilter(authenticationManager, chainedAuthenticationHandler),
                        UsernamePasswordAuthenticationFilter.class
                )
                .addFilterAfter(
                        new QuestionAuthenticationFilter(authenticationManager, chainedAuthenticationHandler),
                        TotpAuthenticationFilter.class
                )
                .addFilterAfter(
                        new FaceAuthenticationFilter(authenticationManager, chainedAuthenticationHandler),
                        QuestionAuthenticationFilter.class
                );

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:4200/index.html")
                .postLogoutRedirectUri("http://localhost:4200/index.html")
                .scopes(config -> config.addAll(List.of(OidcScopes.OPENID, OidcScopes.PROFILE)))
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .build())
                .clientSettings(ClientSettings.builder().requireProofKey(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(client);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.addAllowedOrigin("http://localhost:4200");
        cfg.addAllowedHeader("*");
        cfg.addAllowedMethod("*");
        cfg.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cfg);
        return source;
    }

}
