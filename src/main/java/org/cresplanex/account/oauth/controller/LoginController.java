package org.cresplanex.account.oauth.controller;

import jakarta.servlet.http.HttpSession;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.cresplanex.account.oauth.constants.JwtSettings;
import org.cresplanex.account.oauth.service.TokenBindingService;
import org.cresplanex.account.oauth.service.TokenService;
import org.cresplanex.account.oauth.utils.SecureOpaqueTokenGenerator;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Objects;

@Slf4j
@Controller
@AllArgsConstructor
public class LoginController {

    private final TokenService tokenService;
    private final TokenBindingService tokenBindingService;

    @RequestMapping(value = "/login", method = {RequestMethod.GET})
    public String displayLoginPage(@RequestParam(value = "error", required = false) String error,
                                   @RequestParam(value = "logout", required = false) String logout,
                                   @RequestParam(value = "register", required = false) String register,
                                   HttpSession session,
                                   Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated() && !(authentication.getPrincipal() instanceof String)) {
            return "redirect:/";
        }

        String lastEmail = (String) session.getAttribute("LAST_EMAIL");

        model.addAttribute("email", Objects.requireNonNullElse(lastEmail, ""));

        String errorMesssge = null;
        String logoutMessage = null;
        String registerMessage = null;
        if(null != error) {
            errorMesssge = "Username or Password is incorrect !!";
        }else if(null!= logout) {
            logoutMessage = "You have been successfully logged out !!";
        }else if(null!= register) {
            registerMessage = "You have been successfully registered !!";
        }
        model.addAttribute("errorMessage", errorMesssge);
        model.addAttribute("logoutMessage", logoutMessage);
        model.addAttribute("registerMessage", registerMessage);

        return "login";
    }

    @RequestMapping(value = "/issue-stateless", method = {RequestMethod.GET})
    @ResponseBody
    public ResponseEntity<Object> displayIssueStatelessPage() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        String jwtToken = tokenService.generateJwtToken(authentication);
        String opaqueToken = tokenService.generateOpaqueToken();

        tokenBindingService.bindTokens(opaqueToken, jwtToken, JwtSettings.JWT_OPAQUE_TOKEN_EXCHANGE_EXPIRATION);
        Map<String, Object> response = Map.of("token", opaqueToken, "expiration", JwtSettings.JWT_OPAQUE_TOKEN_EXCHANGE_EXPIRATION);
        return ResponseEntity.ok(response);
    }
}

