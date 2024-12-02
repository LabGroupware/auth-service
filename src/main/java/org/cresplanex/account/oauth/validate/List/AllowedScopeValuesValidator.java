package org.cresplanex.account.oauth.validate.List;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.cresplanex.account.oauth.constants.Scope;

import java.util.Arrays;
import java.util.List;

public class AllowedScopeValuesValidator implements ConstraintValidator<AllowedScopeValues, List<String>> {

    private String[] allowedValues;

    @Override
    public void initialize(AllowedScopeValues constraintAnnotation) {
        this.allowedValues = Scope.ALLOWED_VALUES;
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
