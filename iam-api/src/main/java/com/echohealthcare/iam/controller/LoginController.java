package com.echohealthcare.iam.controller;

import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {

    private final OAuth2AuthorizationConsentService authorizationConsentService;

    public LoginController(OAuth2AuthorizationConsentService authorizationConsentService) {
        this.authorizationConsentService = authorizationConsentService;
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    /**
     * Renders the OAuth2 consent page.
     * Scopes already approved in a previous session are shown as pre-checked/disabled.
     * New scopes are shown as checkboxes the user must actively approve.
     */
    @GetMapping("/oauth2/consent")
    public String consent(
            Principal principal,
            Model model,
            @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
            @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
            @RequestParam(OAuth2ParameterNames.STATE) String state) {

        Set<String> scopesToApprove = new HashSet<>();
        Set<String> previouslyApprovedScopes = new HashSet<>();

        OAuth2AuthorizationConsent previousConsent =
                this.authorizationConsentService.findById(clientId, principal.getName());

        for (String requestedScope : StringUtils.delimitedListToStringArray(scope, " ")) {
            if (previousConsent != null && previousConsent.getScopes().contains(requestedScope)) {
                previouslyApprovedScopes.add(requestedScope);
            } else {
                scopesToApprove.add(requestedScope);
            }
        }

        model.addAttribute("state", state);
        model.addAttribute("clientId", clientId);
        model.addAttribute("scopes", withDescription(scopesToApprove));
        model.addAttribute("previouslyApprovedScopes", withDescription(previouslyApprovedScopes));
        model.addAttribute("principalName", principal.getName());

        return "consent";
    }

    private Set<ScopeWithDescription> withDescription(Set<String> scopes) {
        return scopes.stream()
                .map(ScopeWithDescription::new)
                .collect(Collectors.toSet());
    }

    static class ScopeWithDescription {

        private static final String DEFAULT_DESCRIPTION =
                "UNKNOWN SCOPE — We cannot provide information about this permission. Use caution when granting it.";

        private static final Map<String, String> SCOPE_DESCRIPTIONS = new HashMap<>();

        static {
            SCOPE_DESCRIPTIONS.put("openid",  "Verify your identity via OpenID Connect");
            SCOPE_DESCRIPTIONS.put("profile", "Read your basic profile information");
            SCOPE_DESCRIPTIONS.put("email",   "Read your email address");
            SCOPE_DESCRIPTIONS.put("address", "Read your address information");
            SCOPE_DESCRIPTIONS.put("phone",   "Read your phone number");
        }

        public final String scope;
        public final String description;

        ScopeWithDescription(String scope) {
            this.scope = scope;
            this.description = SCOPE_DESCRIPTIONS.getOrDefault(scope, DEFAULT_DESCRIPTION);
        }
    }
}
