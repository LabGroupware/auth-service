package org.cresplanex.account.oauth.validate.List;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.cresplanex.account.oauth.constants.Scope;
import org.cresplanex.account.oauth.constants.SupportClientAuthenticationMethods;

import java.util.Arrays;
import java.util.List;

public class AllowedAuthenticationMethodsValidator implements ConstraintValidator<AllowedAuthenticationMethods, List<String>> {

    private String[] allowedValues;

    @Override
    public void initialize(AllowedAuthenticationMethods constraintAnnotation) {
        this.allowedValues = SupportClientAuthenticationMethods.SUPPORTED_CLIENT_AUTHENTICATION_METHODS;
    }

    @Override
    public boolean isValid(List<String> value, ConstraintValidatorContext context) {
        if (value == null) {
            return true; // nullは他のバリデーションに任せます
        }

        for (String v : value) {
            if (!Arrays.asList(allowedValues).contains(v)) {
                return false;
            }
        }
        return true;
    }
}
