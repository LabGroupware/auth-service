package org.cresplanex.account.oauth.validate.List;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.cresplanex.account.oauth.constants.SupportAuthorizationGrantType;

import java.util.Arrays;
import java.util.List;

public class AllowedGrantTypesValidator implements ConstraintValidator<AllowedGrantTypes, List<String>> {

    private String[] allowedValues;

    @Override
    public void initialize(AllowedGrantTypes constraintAnnotation) {
        this.allowedValues = SupportAuthorizationGrantType.SUPPORTED_AUTHORIZATION_GRANT_TYPES;
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
