package org.cresplanex.account.oauth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.cresplanex.account.oauth.auth.CustomAccessDeniedHandler;
import org.cresplanex.account.oauth.auth.CustomAuthenticationEntryPoint;
import org.cresplanex.account.oauth.auth.OAuthAuthenticationFailureHandler;
import org.cresplanex.account.oauth.auth.UsernamePwdAuthenticationProvider;
import org.cresplanex.account.oauth.auth.filter.JWTTokenValidatorFilter;
import org.cresplanex.account.oauth.constants.Scope;
import org.cresplanex.account.oauth.constants.SessionManagement;
import org.cresplanex.account.oauth.entity.UserEntity;
import org.cresplanex.account.oauth.repository.AccountRepository;
import org.cresplanex.account.oauth.utils.CommonUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Collectors;

@Slf4j
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {

    @Value("${app.grant-ip-ciders}")
    private String grantIpCidrs;

    @Value("${app.front.origins}")
    private String frontOrigins;

    @Value("${app.require-https}")
    private boolean requireHttps;

    private final AccountRepository accountRepository;

    private final OAuthAuthenticationFailureHandler oAuthAuthenticationFailureHandler;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults())    // Enable OpenID Connect 1.0
                .authorizationEndpoint(authorizationEndpoint -> {
                    authorizationEndpoint.consentPage("/oauth2/consent");
                    authorizationEndpoint.errorResponseHandler(oAuthAuthenticationFailureHandler);
                });
        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                // Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults()));


        return http.build();
    }

    private boolean isIpInCidrRange(String clientIp) {
        boolean granted = false;
        List<String> cidrRanges = List.of(grantIpCidrs.split(","));
        if (CommonUtil.isDebugEnabled()) {
            return true;
        } else {
            for (String range : cidrRanges) {
                IpAddressMatcher matcher = new IpAddressMatcher(range);
                granted = matcher.matches(clientIp);
                if (granted) {
                    break;
                }
            }
        }

        return granted;
    }

    @Bean
    @Order(3)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers(HttpMethod.POST, "/register", "/login").not().authenticated()
                        .requestMatchers("/register", "/login", "/css/**", "/js/**",  "/forgot-password", "/error/**").permitAll()
                        .requestMatchers("/actuator/**").access(
                                new AuthorizationManager<RequestAuthorizationContext>() {
                                    @Override
                                    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
                                        String ClientIp = object.getRequest().getRemoteAddr();
                                        boolean granted = isIpInCidrRange(ClientIp);
                                        return new AuthorizationDecision(granted);
                                    }
                                })
                        .anyRequest().authenticated()
                )
                .formLogin(formLogin ->
                        formLogin
                                .loginPage("/login")
                                .usernameParameter("email")
                                .passwordParameter("password")
                                .loginProcessingUrl("/login")
                                .failureUrl("/login?error=true")
                )
                .logout(logout ->
                        logout
                                .logoutRequestMatcher(
                                        (request) -> request.getServletPath().equals("/logout")
                                )
                                .logoutSuccessUrl("/login?logout=true")
                                .invalidateHttpSession(true)
                                .clearAuthentication(true)
                                .deleteCookies("JSESSIONID")
                )
                .sessionManagement(session -> session
                        .maximumSessions(SessionManagement.MAXIMUM_SESSIONS)
                        .maxSessionsPreventsLogin(SessionManagement.MAX_SESSIONS_PREVENTS_LOGIN)
                );

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain jwtSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher((request) -> {
                    String path = request.getServletPath();
                    return path.startsWith("/api");
                })
                .sessionManagement(sessionConfig -> sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .cors(corsConfig -> corsConfig.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(@NonNull HttpServletRequest request) {
                        CorsConfiguration config = new CorsConfiguration();

                        List<String> origins = List.of(frontOrigins.split(","));

                        config.setAllowedOrigins(origins); // 許可するオリジン
                        config.setAllowedMethods(Collections.singletonList("*")); // 全てのHTTPメソッドを許可
                        config.setAllowCredentials(true); // クレデンシャル（Cookieや認証情報）を許可
                        config.setAllowedHeaders(Collections.singletonList("*")); // 全てのヘッダーを許可
                        config.setExposedHeaders(List.of("Authorization")); // レスポンスヘッダーに含めるヘッダー
                        config.setMaxAge(3600L); // プリフライトリクエストのキャッシュ時間
                        return config;
                    }
                }))
                .csrf(AbstractHttpConfigurer::disable)
                .addFilterBefore(new JWTTokenValidatorFilter(), BasicAuthenticationFilter.class)
                .requiresChannel(
                        rcc -> {
                            if (requireHttps) {
                                rcc.anyRequest().requiresSecure();
                            }
                        }
                )
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/api/auth/login/**").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(
                        ehc -> ehc
                                .accessDeniedHandler(new CustomAccessDeniedHandler())
                                .authenticationEntryPoint(new CustomAuthenticationEntryPoint())
                );

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return (context) -> {
            UserEntity userEntity = accountRepository.findUserByLoginId(context.getPrincipal().getName()).orElseThrow();

            context.getClaims().claims((claims) -> {
                claims.replace(JwtClaimNames.SUB, userEntity.getUserId());
            });

            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                OidcUserInfo.Builder userInfoBuilder = OidcUserInfo.builder()
                        .subject(userEntity.getUserId());
                OAuth2Authorization authorization = context.getAuthorization();
                if (authorization != null) {
                    Set<String> scopes = authorization.getAuthorizedScopes();
                    if (scopes.contains(Scope.PROFILE)) {
                        userInfoBuilder
                                .name(userEntity.getName())
                                .birthdate(userEntity.getBirthdate() == null ? null :userEntity.getBirthdate().format(DateTimeFormatter.ISO_DATE))
                                .givenName(userEntity.getGivenName())
                                .familyName(userEntity.getFamilyName())
                                .middleName(userEntity.getMiddleName())
                                .nickname(userEntity.getNickname())
                                .preferredUsername(userEntity.getPreferredUsername())
                                .profile(userEntity.getProfile())
                                .picture(userEntity.getPicture())
                                .website(userEntity.getWebsite())
                                .gender(userEntity.getGender())
                                .locale(userEntity.getLocale())
                                .zoneinfo(userEntity.getZoneinfo())
                                .updatedAt(userEntity.getUpdatedAt() == null ? null : userEntity.getUpdatedAt().format(DateTimeFormatter.ISO_DATE_TIME));
                    }
                    if (scopes.contains(Scope.EMAIL)) {
                        userInfoBuilder.email(userEntity.getEmail());
                    }
                    if (scopes.contains(Scope.ADDRESS)) {
                        userInfoBuilder.address(userEntity.getAddress());
                    }
                    if (scopes.contains(Scope.PHONE)) {
                        userInfoBuilder.phoneNumber(userEntity.getPhone());
                    }
                }

                OidcUserInfo userInfo = userInfoBuilder.build();
                context.getClaims().claims(claims ->
                        claims.putAll(userInfo.getClaims()));
            }

            if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
                context.getClaims().claims((claims) -> {
                    if (context.getAuthorizationGrantType().equals(AuthorizationGrantType.CLIENT_CREDENTIALS)) {
                        Set<String> roles = context.getClaims().build().getClaim("scope");
                        claims.put("roles", roles);
                    } else if (context.getAuthorizationGrantType().equals(AuthorizationGrantType.AUTHORIZATION_CODE)) {
                        Set<String> roles = AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities())
                                .stream()
                                .map(c -> c.replaceFirst("^ROLE_", ""))
                                .collect(Collectors.collectingAndThen(Collectors.toSet(), Collections::unmodifiableSet));
                        claims.put("roles", roles);
                    }
                });
            }
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * From Spring Security 6.3 version
     *
     * @return CompromisedPasswordChecker
     */
    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService,
                                                       PasswordEncoder passwordEncoder) {
        UsernamePwdAuthenticationProvider authenticationProvider =
                new UsernamePwdAuthenticationProvider(userDetailsService, passwordEncoder);
        ProviderManager providerManager = new ProviderManager(authenticationProvider);
        providerManager.setEraseCredentialsAfterAuthentication(false);
        return  providerManager;
    }

}
