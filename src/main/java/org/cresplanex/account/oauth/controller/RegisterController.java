package org.cresplanex.account.oauth.controller;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.cresplanex.account.oauth.dto.account.RegisterAccountRequestDto;
import org.cresplanex.account.oauth.entity.AccountEntity;
import org.cresplanex.account.oauth.exception.AccountDuplicateException;
import org.cresplanex.account.oauth.service.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;

@Slf4j
@Controller
@AllArgsConstructor
@SessionAttributes("registerAccountRequestDTO")
public class RegisterController {

    private UserService userService;

    @ModelAttribute("registerAccountRequestDTO")
    public RegisterAccountRequestDto registerAccountRequestDTO() {
        return new RegisterAccountRequestDto();
    }

    @RequestMapping(value = "/register", method = {RequestMethod.GET})
    public String registerForm(SessionStatus sessionStatus, Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated() && !(authentication.getPrincipal() instanceof String)) {
            return "redirect:/";
        }

        sessionStatus.setComplete();
        model.addAttribute("registerAccountRequestDTO", new RegisterAccountRequestDto());
        return "register";
    }

    @RequestMapping(value = "/register", method = {RequestMethod.POST})
    public String register(
            @ModelAttribute("registerAccountRequestDTO") @Valid RegisterAccountRequestDto dto,
            BindingResult bindingResult,
            SessionStatus sessionStatus,
            Model model
    ) {
        // Check for validation errors
        if (bindingResult.hasErrors()) {
            model.addAttribute("errorMessage", "Validation error occurred.");
            dto.setPassword(null);
            dto.setPasswordConfirm(null);
            return "register";
        }
        AccountEntity accountEntity = new AccountEntity();
        accountEntity.setLoginId(dto.getEmail());

        try{
            userService.create(
                    accountEntity,
                    dto.getPassword(),
                    dto.getName(),
                    dto.getEmail()
            );
            sessionStatus.setComplete();
            return "redirect:/login?register=true";
        } catch (AccountDuplicateException e) {
            if (e.getUniqueType() == AccountDuplicateException.UniqueType.LOGIN_ID) {
                model.addAttribute("errorMessage", "Sorry, this email is already in use.");
                return "register";
            }
            throw new RuntimeException("Unexpected exception occurred.", e);
        }
    }
}
