package org.cresplanex.account.oauth.service;

import org.cresplanex.account.oauth.constants.OAuthClientSettings;
import org.cresplanex.account.oauth.constants.SupportAuthorizationGrantType;
import org.cresplanex.account.oauth.constants.SupportClientAuthenticationMethods;
import org.cresplanex.account.oauth.entity.Oauth2RegisteredClientEntity;
import org.cresplanex.account.oauth.repository.Oauth2RegisteredClientRepository;
import org.cresplanex.account.oauth.utils.CustomIdGenerator;
import org.cresplanex.account.oauth.utils.SecureOpaqueTokenGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.*;

@Service
public class Oauth2RegisteredClientService {
    private final Oauth2RegisteredClientRepository repository;
    private final RegisteredClientRepository jdbcRegisteredClientRepository;
    private final CustomIdGenerator customIdGenerator;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public Oauth2RegisteredClientService(Oauth2RegisteredClientRepository repository, RegisteredClientRepository registeredClientRepository, PasswordEncoder passwordEncoder) {
        this.repository = repository;
        this.jdbcRegisteredClientRepository = registeredClientRepository;
        this.customIdGenerator = new CustomIdGenerator();
        this.passwordEncoder = passwordEncoder;
    }

    public Oauth2RegisteredClientEntity createClient(
            Oauth2RegisteredClientEntity client,
            List<String> authorizationGrantTypes,
            List<String> clientAuthenticationMethods,
            List<String> scopes,
            List<String> redirectUris,
            List<String> postLogoutRedirectUris) {
        String id = UUID.randomUUID().toString();
        client.setId(id);

        String clientId = customIdGenerator.generate();
        client.setClientId(clientId);

        String clientSecret = SecureOpaqueTokenGenerator.generateToken();
        client.setClientSecret(clientSecret);
        String hashedClientSecret = passwordEncoder.encode(clientSecret);

        RegisteredClient.Builder registeredClient = RegisteredClient.withId(id)
                .clientId(clientId)
                .clientSecret(hashedClientSecret)
                .clientName(client.getClientName());

        Set<String> grantTypes = new HashSet<>(authorizationGrantTypes);

        for (String authorizationGrantType : grantTypes) {

            switch (authorizationGrantType) {
                case SupportAuthorizationGrantType.AUTHORIZATION_CODE:
                    registeredClient.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
                    break;
                case SupportAuthorizationGrantType.REFRESH_TOKEN:
                    registeredClient.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
                    break;
                case SupportAuthorizationGrantType.CLIENT_CREDENTIALS:
                    registeredClient.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
                    break;
                case SupportAuthorizationGrantType.PASSWORD:
                    registeredClient.authorizationGrantType(AuthorizationGrantType.PASSWORD);
                    break;
                case SupportAuthorizationGrantType.JWT_BEARER:
                    registeredClient.authorizationGrantType(AuthorizationGrantType.JWT_BEARER);
                    break;
                case SupportAuthorizationGrantType.DEVICE_CODE:
                    registeredClient.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE);
                    break;
                case SupportAuthorizationGrantType.TOKEN_EXCHANGE:
                    registeredClient.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);
                    break;
                default:
                    break;
            }
        }

        Set<String> clientAuthMethods = new HashSet<>(clientAuthenticationMethods);

        for (String clientAuthenticationMethod : clientAuthMethods) {
            switch (clientAuthenticationMethod) {
                case SupportClientAuthenticationMethods.CLIENT_SECRET_BASIC:
                    registeredClient.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
                    break;
                case SupportClientAuthenticationMethods.CLIENT_SECRET_POST:
                    registeredClient.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
                    break;
                case SupportClientAuthenticationMethods.CLIENT_SECRET_JWT:
                    registeredClient.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT);
                    break;
                case SupportClientAuthenticationMethods.PRIVATE_KEY_JWT:
                    registeredClient.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
                    break;
                case SupportClientAuthenticationMethods.NONE:
                    registeredClient.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
                    break;
                case SupportClientAuthenticationMethods.TLS_CLIENT_AUTH:
                    registeredClient.clientAuthenticationMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH);
                    break;
                case SupportClientAuthenticationMethods.SELF_SIGNED_TLS_CLIENT_AUTH:
                    registeredClient.clientAuthenticationMethod(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH);
                    break;
                default:
                    break;
            }
        }
        Set<String> scopesSet = new HashSet<>(scopes);
        scopesSet.forEach(registeredClient::scope);
        Set<String> redirectUrisSet = new HashSet<>(redirectUris);
        redirectUrisSet.forEach(registeredClient::redirectUri);
        Set<String> postLogoutRedirectUrisSet = new HashSet<>(postLogoutRedirectUris);
        postLogoutRedirectUrisSet.forEach(registeredClient::postLogoutRedirectUri);

        registeredClient.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(OAuthClientSettings.ACCESS_TOKEN_TIME_TO_LIVE))
                        .refreshTokenTimeToLive(Duration.ofHours(OAuthClientSettings.REFRESH_TOKEN_TIME_TO_LIVE))
                        .reuseRefreshTokens(OAuthClientSettings.REUSE_REFRESH_TOKENS)
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .build())
                .build();
        jdbcRegisteredClientRepository.save(registeredClient.build());
        return client;
    }

    public Optional<Oauth2RegisteredClientEntity> getClientById(String id) {
        return repository.findById(id);
    }

//    public Optional<Oauth2RegisteredClientEntity> getClientByClientId(String clientId) {
//        return repository.findByClientId(clientId);
//    }
//
//    public List<Oauth2RegisteredClientEntity> getAllClients() {
//        return repository.findAll();
//    }

//    public Oauth2RegisteredClientEntity updateClient(String id, Oauth2RegisteredClientEntity updatedClient) {
//        return repository.findById(id)
//                .map(client -> {
//                    client.setClientName(updatedClient.getClientName());
//                    client.setRedirectUris(updatedClient.getRedirectUris());
//                    client.setScopes(updatedClient.getScopes());
//                    client.setClientAuthenticationMethods(updatedClient.getClientAuthenticationMethods());
//                    client.setAuthorizationGrantTypes(updatedClient.getAuthorizationGrantTypes());
//                    client.setClientSettings(updatedClient.getClientSettings());
//                    client.setTokenSettings(updatedClient.getTokenSettings());
//                    return repository.save(client);
//                }).orElseThrow(() -> new RuntimeException("Client not found: " + id));
//    }
//
//    public void deleteClient(String id) {
//        if (repository.existsById(id)) {
//            repository.deleteById(id);
//        } else {
//            throw new RuntimeException("Client not found: " + id);
//        }
//    }
}
