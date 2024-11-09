package org.cresplanex.account.oauth.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.cresplanex.account.oauth.constants.Scope;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.*;

@Slf4j
@Controller
@RequiredArgsConstructor
public class AuthorizationConsentController {
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationConsentService authorizationConsentService;

    @RequestMapping(value = "/oauth2/consent", method = RequestMethod.GET)
    public String consent(Principal principal, Model model,
                          @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
                          @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
                          @RequestParam(OAuth2ParameterNames.STATE) String state) {

        Set<String> scopesToApprove = new LinkedHashSet<>();

        if (clientId == null) {
            return "invalid-clientid";
        }

        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            return "invalid-clientid";
        }
        Set<String> needDescriptionScopes = new HashSet<>();
        Set<String> scopes = registeredClient.getScopes();

        for (String requestedScope : StringUtils.delimitedListToStringArray(scope, " ")) {
            if (scopes.contains(requestedScope)) { // サポートしているスコープのみ承認
                scopesToApprove.add(requestedScope);
                needDescriptionScopes.add(requestedScope);
            }
        }

        scopesToApprove.remove(Scope.OPENID);

        OAuth2AuthorizationConsent authorizationConsent = this.authorizationConsentService.findById(registeredClient.getId(), principal.getName());

        Set<String> approvedScopes = new HashSet<>();
        if (authorizationConsent != null) {
            approvedScopes = authorizationConsent.getScopes();
            for (String approvedScope : approvedScopes) {
                scopesToApprove.remove(approvedScope);
                approvedScopes.add(approvedScope);
                needDescriptionScopes.add(approvedScope);
            }
        }

        model.addAttribute("clientId", clientId);
        model.addAttribute("clientName", registeredClient.getClientName());
        model.addAttribute("state", state);
        model.addAttribute("scopes", withDescription(needDescriptionScopes));
        model.addAttribute("approvedScopes", withDescription(approvedScopes));
        model.addAttribute("scopesToApprove", withDescription(scopesToApprove));
        model.addAttribute("principalName", principal.getName());
        model.addAttribute("redirectUri", registeredClient.getRedirectUris().iterator().next());
        model.addAttribute("responseTypes", registeredClient.getAuthorizationGrantTypes());

        return "consent";
    }

    private static Set<ScopeWithDescription> withDescription(Set<String> scopes) {
        Set<ScopeWithDescription> scopeWithDescriptions = new LinkedHashSet<>();
        for (String scope : scopes) {
            scopeWithDescriptions.add(new ScopeWithDescription(scope));

        }
        return scopeWithDescriptions;
    }

    public static class ScopeWithDescription {
        private static final String DEFAULT_DESCRIPTION = "No description available";
        private static final Map<String, String> scopeDescriptions = new HashMap<>();

        static {
            scopeDescriptions.put(
                    Scope.OPENID,
                    "Authenticate using OpenID Connect");
            scopeDescriptions.put(
                    Scope.PROFILE,
                    "Access your basic profile information");
            scopeDescriptions.put(
                    Scope.EMAIL,
                    "Access your email address");
            scopeDescriptions.put(
                    Scope.ADDRESS,
                    "Access your address");
            scopeDescriptions.put(
                    Scope.PHONE,
                    "Access your phone number");
            scopeDescriptions.put(
                    Scope.READ,
                    "Read your data");
            scopeDescriptions.put(
                    Scope.WRITE,
                    "Write your data");
        }

        public final String scope;
        public final String description;

        ScopeWithDescription(String scope) {
            this.scope = scope;
            this.description = scopeDescriptions.getOrDefault(scope, DEFAULT_DESCRIPTION);
        }
    }

    // TODO: 許可スコープの削除エンドポイントの作成
}

