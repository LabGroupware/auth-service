package org.cresplanex.account.oauth.validate.Enum;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

public class ListOfEnumValidator implements ConstraintValidator<ValidEnumList, List<String>> {

    private List<String> acceptedValues;

    @Override
    public void initialize(ValidEnumList constraintAnnotation) {
        Class<? extends Enum<?>> enumClass = constraintAnnotation.enumClass();
        acceptedValues = Arrays.stream(enumClass.getEnumConstants())
                .map(Enum::name)
                .toList(); // Enumの値を取得
    }

    @Override
    public boolean isValid(List<String> values, ConstraintValidatorContext context) {
        if (values == null || values.isEmpty()) {
            return true;
        }

        return new HashSet<>(acceptedValues).containsAll(values);
    }
}
