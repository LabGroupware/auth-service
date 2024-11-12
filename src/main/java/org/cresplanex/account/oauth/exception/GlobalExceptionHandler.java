package org.cresplanex.account.oauth.exception;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.cresplanex.account.oauth.constants.AuthServerErrorCode;
import org.cresplanex.account.oauth.dto.api.ErrorAttributeDto;
import org.cresplanex.account.oauth.dto.api.ErrorResponseDto;
import org.cresplanex.account.oauth.service.HtmlRenderingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingPathVariableException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Slf4j
@ControllerAdvice
public class GlobalExceptionHandler {

    @Autowired
    private HtmlRenderingService htmlRenderingService;

    private boolean isHtmlRequest(HttpServletRequest request) {
        String acceptHeader = request.getHeader("Accept");

        return acceptHeader != null && acceptHeader.contains("text/html");
    }

    // Validation Error
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        if (isHtmlRequest(request)) {
            Map<String, Object> variables = new HashMap<>();
            String htmlContent = htmlRenderingService.renderHtml(request, response,"error/400", variables);
            return new ResponseEntity<>(htmlContent, HttpStatus.BAD_REQUEST);
        }

        ErrorAttributeDto errorAttributeDTO = getErrorAttributeDto(ex, request);

        ErrorResponseDto errorResponseDTO = ErrorResponseDto.create(
                AuthServerErrorCode.VALIDATION_ERROR,
                "Validation Error",
                errorAttributeDTO
        );

        return new ResponseEntity<>(errorResponseDTO, HttpStatus.BAD_REQUEST);
    }

    private static ErrorAttributeDto getErrorAttributeDto(MethodArgumentNotValidException ex, HttpServletRequest request) {
        Map<String, String> validationErrors = new HashMap<>();
        List<ObjectError> validationErrorList = ex.getBindingResult().getAllErrors();

        validationErrorList.forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String validationMsg = error.getDefaultMessage();
            validationErrors.put(fieldName, validationMsg);
        });

        return new ErrorAttributeDto(
                request.getRequestURI(),
                validationErrors
        );
    }

    // HTTP Method Not Supported
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<Object> handleHttpRequestMethodNotSupported(
             HttpRequestMethodNotSupportedException ex,
             HttpServletRequest request,
             HttpServletResponse response
    ) {

        if (isHtmlRequest(request)) {
            Map<String, Object> variables = new HashMap<>();
            String htmlContent = htmlRenderingService.renderHtml(request, response,"error/405", variables);
            return new ResponseEntity<>(htmlContent, HttpStatus.METHOD_NOT_ALLOWED);
        }

        Map<String, String> errorAttributes = new HashMap<>();
        errorAttributes.put("supportedMethods", Objects.requireNonNull(ex.getSupportedHttpMethods()).toString());
        errorAttributes.put("requestMethod", ex.getMethod());
        errorAttributes.put("requestUrl", request.getRequestURI());

        ErrorAttributeDto errorAttributeDTO = new ErrorAttributeDto(
                request.getRequestURI(),
                errorAttributes
        );

        ErrorResponseDto errorResponseDTO = ErrorResponseDto.create(
                AuthServerErrorCode.METHOD_NOT_ALLOWED,
                "Method Not Supported",
                errorAttributeDTO
        );

        return new ResponseEntity<>(errorResponseDTO, HttpStatus.METHOD_NOT_ALLOWED);
    }

    // サポートされていないContent-Type
    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<Object> handleHttpMediaTypeNotSupported(
             HttpMediaTypeNotSupportedException ex, HttpServletRequest request,  HttpServletResponse response) {

        if (isHtmlRequest(request)) {
            Map<String, Object> variables = new HashMap<>();
            String htmlContent = htmlRenderingService.renderHtml(request, response, "error/415", variables);
            return new ResponseEntity<>(htmlContent, HttpStatus.UNSUPPORTED_MEDIA_TYPE);
        }

        Map<String, Object> errorAttributes = new HashMap<>();
        errorAttributes.put("supportedMediaTypes", ex.getSupportedMediaTypes().toString());
        errorAttributes.put("contentType", ex.getContentType());

        ErrorAttributeDto errorAttributeDTO = new ErrorAttributeDto(
                request.getRequestURI(),
                errorAttributes
        );

        ErrorResponseDto errorResponseDTO = ErrorResponseDto.create(
                AuthServerErrorCode.NOT_SUPPORT_CONTENT_TYPE,
                "Media Type Not Supported",
                errorAttributeDTO
        );

        return new ResponseEntity<>(errorResponseDTO, HttpStatus.UNSUPPORTED_MEDIA_TYPE);
    }

    // Missing Path Variable
    @ExceptionHandler(MissingPathVariableException.class)
    public ResponseEntity<Object> handleMissingPathVariable(
             MissingPathVariableException ex, HttpServletRequest request,  HttpServletResponse response) {

        if (isHtmlRequest(request)) {
            Map<String, Object> variables = new HashMap<>();
            String htmlContent = htmlRenderingService.renderHtml(request, response, "error/400", variables);
            return new ResponseEntity<>(htmlContent, HttpStatus.BAD_REQUEST);
        }

        Map<String, String> errorAttributes = new HashMap<>();
        errorAttributes.put("parameterName", ex.getVariableName());
        errorAttributes.put("parameterType", ex.getParameter().getParameterType().getSimpleName());

        ErrorAttributeDto errorAttributeDTO = new ErrorAttributeDto(
                request.getRequestURI(),
                errorAttributes
        );

        ErrorResponseDto errorResponseDTO = ErrorResponseDto.create(
                AuthServerErrorCode.MISSING_PATH_VARIABLE,
                "Validation Error",
                errorAttributeDTO
        );

        return new ResponseEntity<>(errorResponseDTO, HttpStatus.BAD_REQUEST);
    }

    // Max Upload Size Exceeded
    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<Object> handleMaxUploadSizeExceededException(
             MaxUploadSizeExceededException ex,  HttpServletRequest request, HttpServletResponse response) {

        if (isHtmlRequest(request)) {
            Map<String, Object> variables = new HashMap<>();
            String htmlContent = htmlRenderingService.renderHtml(request, response, "error/413", variables);
            return new ResponseEntity<>(htmlContent, HttpStatus.PAYLOAD_TOO_LARGE);
        }

        Map<String, String> errorAttributes = new HashMap<>();
        errorAttributes.put("maxUploadSize", ex.getMaxUploadSize() + " bytes");

        ErrorAttributeDto errorAttributeDTO = new ErrorAttributeDto(
                request.getRequestURI(),
                errorAttributes
        );

        ErrorResponseDto errorResponseDTO = ErrorResponseDto.create(
                AuthServerErrorCode.EXCEED_MAX_UPLOAD_SIZE,
                "Validation Error",
                errorAttributeDTO
        );

        return new ResponseEntity<>(errorResponseDTO, HttpStatus.PAYLOAD_TOO_LARGE);
    }

    // No Resource Found
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<Object> handleNoResourceFoundException(
             NoResourceFoundException ex,  HttpServletRequest request, HttpServletResponse response) {

        if (isHtmlRequest(request)) {
            Map<String, Object> variables = new HashMap<>();
            String htmlContent = htmlRenderingService.renderHtml(request, response, "error/404", variables);
            return new ResponseEntity<>(htmlContent, HttpStatus.NOT_FOUND);
        }

        Map<String, String> errorAttributes = new HashMap<>();
        errorAttributes.put("requestUrl", request.getRequestURI());

        ErrorAttributeDto errorAttributeDTO = new ErrorAttributeDto(
                request.getRequestURI(),
                errorAttributes
        );

        ErrorResponseDto errorResponseDTO = ErrorResponseDto.create(
                AuthServerErrorCode.NOT_FOUND_HANDLER,
                "Not Found",
                errorAttributeDTO
        );

        return new ResponseEntity<>(errorResponseDTO, HttpStatus.NOT_FOUND);
    }

    // Not Found Handler
    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<Object> handleNoHandlerFoundException(
             NoHandlerFoundException ex,  HttpServletRequest request, HttpServletResponse response) {

        if (isHtmlRequest(request)) {
            Map<String, Object> variables = new HashMap<>();
            String htmlContent = htmlRenderingService.renderHtml(request, response, "error/404", variables);
            return new ResponseEntity<>(htmlContent, HttpStatus.NOT_FOUND);
        }

        Map<String, String> errorAttributes = new HashMap<>();
        errorAttributes.put("requestMethod", ex.getHttpMethod());
        errorAttributes.put("requestUrl", ex.getRequestURL());

        ErrorAttributeDto errorAttributeDTO = new ErrorAttributeDto(
                request.getRequestURI(),
                errorAttributes
        );

        ErrorResponseDto errorResponseDTO = ErrorResponseDto.create(
                AuthServerErrorCode.NOT_FOUND_HANDLER,
                "Internal Server Error",
                errorAttributeDTO
        );

        return new ResponseEntity<>(errorResponseDTO, HttpStatus.NOT_FOUND);
    }

    // not readable
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Object> handleHttpMessageNotReadable(
             HttpMessageNotReadableException ex,  HttpServletRequest request, HttpServletResponse response) {

        if (isHtmlRequest(request)) {
            Map<String, Object> variables = new HashMap<>();
            String htmlContent = htmlRenderingService.renderHtml(request, response, "error/400", variables);
            return new ResponseEntity<>(htmlContent, HttpStatus.BAD_REQUEST);
        }

        Map<String, String> errorAttributes = new HashMap<>();

        ErrorAttributeDto errorAttributeDTO = new ErrorAttributeDto(
                request.getRequestURI(),
                errorAttributes
        );

        ErrorResponseDto errorResponseDTO = ErrorResponseDto.create(
                AuthServerErrorCode.NOT_READABLE_REQUEST,
                "Not Readable Request",
                errorAttributeDTO
        );

        return new ResponseEntity<>(errorResponseDTO, HttpStatus.BAD_REQUEST);
    }


    // Authentication Failed
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Object> handleAuthenticationException(
            AuthenticationException ex, HttpServletRequest request, HttpServletResponse response) {
        if (isHtmlRequest(request)) {
            Map<String, Object> variables = new HashMap<>();
            String htmlContent = htmlRenderingService.renderHtml(request, response, "error/401", variables);
            return new ResponseEntity<>(htmlContent, HttpStatus.UNAUTHORIZED);
        }

        ErrorAttributeDto errorAttributeDTO = new ErrorAttributeDto(
                request.getRequestURI(),
                null
        );

        ErrorResponseDto errorResponseDTO = ErrorResponseDto.create(
                AuthServerErrorCode.AUTHENTICATION_FAILED,
                "Authentication Error",
                errorAttributeDTO
        );

        return new ResponseEntity<>(errorResponseDTO, HttpStatus.UNAUTHORIZED);
    }

    // Access Denied
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Object> handleAccessDeniedException(
            AccessDeniedException ex, HttpServletRequest request, HttpServletResponse response) {
        if (isHtmlRequest(request)) {
            Map<String, Object> variables = new HashMap<>();
            String htmlContent = htmlRenderingService.renderHtml(request, response, "error/403", variables);
            return new ResponseEntity<>(htmlContent, HttpStatus.FORBIDDEN);
        }

        Map<String, String> errorAttributes = new HashMap<>();
        errorAttributes.put("message", ex.getMessage());

        ErrorAttributeDto errorAttributeDTO = new ErrorAttributeDto(
                request.getRequestURI(),
                errorAttributes
        );

        ErrorResponseDto errorResponseDTO = ErrorResponseDto.create(
                AuthServerErrorCode.ACCESS_DENIED,
                "Access Denied",
                errorAttributeDTO
        );

        return new ResponseEntity<>(errorResponseDTO, HttpStatus.FORBIDDEN);
    }

    // Method Argument Type Mismatch
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<Object> handleMethodArgumentTypeMismatch(
            MethodArgumentTypeMismatchException ex, HttpServletRequest request, HttpServletResponse response) {
        if (isHtmlRequest(request)) {
            Map<String, Object> variables = new HashMap<>();
            String htmlContent = htmlRenderingService.renderHtml(request, response, "error/400", variables);
            return new ResponseEntity<>(htmlContent, HttpStatus.BAD_REQUEST);
        }

        Map<String, Object> errorAttributes = new HashMap<>();
        errorAttributes.put("parameterName", ex.getName());
        errorAttributes.put("parameterValue", ex.getValue());
        errorAttributes.put("parameterType", Objects.requireNonNull(ex.getRequiredType()).getSimpleName());

        ErrorAttributeDto errorAttributeDTO = new ErrorAttributeDto(
                request.getRequestURI(),
                errorAttributes
        );

        ErrorResponseDto errorResponseDTO = ErrorResponseDto.create(
                AuthServerErrorCode.METHOD_ARGUMENT_TYPE_MISMATCH,
                "Validation Error",
                errorAttributeDTO
        );

        return new ResponseEntity<>(errorResponseDTO, HttpStatus.BAD_REQUEST);
    }

    // Account Duplicate Exception
    @ExceptionHandler(AccountDuplicateException.class)
    public ResponseEntity<Object> handleAccountDuplicateException(
            AccountDuplicateException exception, HttpServletRequest request, HttpServletResponse response) {
        if (isHtmlRequest(request)) {
            Map<String, Object> variables = new HashMap<>();
            String htmlContent = htmlRenderingService.renderHtml(request, response, "error/400", variables);
            return new ResponseEntity<>(htmlContent, HttpStatus.BAD_REQUEST);
        }

        Map<String, String> errorAttributes = new HashMap<>();
        errorAttributes.put("needUniqueType", exception.getUniqueType().name());
        errorAttributes.put("needUniqueValue", exception.getUniqueValue().toString());

        ErrorAttributeDto errorAttributeDTO = new ErrorAttributeDto(
                request.getRequestURI(),
                errorAttributes
        );

        ErrorResponseDto errorResponseDTO = ErrorResponseDto.create(
                AuthServerErrorCode.ACCOUNT_ALREADY_EXISTS,
                exception.getErrorCaption(),
                errorAttributeDTO
        );

        return new ResponseEntity<>(errorResponseDTO, HttpStatus.BAD_REQUEST);
    }

    // User Duplicate Exception
    @ExceptionHandler(UserDuplicateException.class)
    public ResponseEntity<Object> handleUserDuplicateException(
            UserDuplicateException exception, HttpServletRequest request, HttpServletResponse response) {
        if (isHtmlRequest(request)) {
            Map<String, Object> variables = new HashMap<>();
            String htmlContent = htmlRenderingService.renderHtml(request, response, "error/400", variables);
            return new ResponseEntity<>(htmlContent, HttpStatus.BAD_REQUEST);
        }

        Map<String, String> errorAttributes = new HashMap<>();
        errorAttributes.put("needUniqueType", exception.getUniqueType().name());
        errorAttributes.put("needUniqueValue", exception.getUniqueValue().toString());

        ErrorAttributeDto errorAttributeDTO = new ErrorAttributeDto(
                request.getRequestURI(),
                errorAttributes
        );

        ErrorResponseDto errorResponseDTO = ErrorResponseDto.create(
                AuthServerErrorCode.USER_ALREADY_EXISTS,
                exception.getErrorCaption(),
                errorAttributeDTO
        );

        return new ResponseEntity<>(errorResponseDTO, HttpStatus.BAD_REQUEST);
    }

    // User Not Found Exception
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<Object> handleUserNotFoundException(
            UserNotFoundException exception, HttpServletRequest request, HttpServletResponse response) {
        if (isHtmlRequest(request)) {
            Map<String, Object> variables = new HashMap<>();
            String htmlContent = htmlRenderingService.renderHtml(request, response, "error/404", variables);
            return new ResponseEntity<>(htmlContent, HttpStatus.NOT_FOUND);
        }

        Map<String, String> errorAttributes = new HashMap<>();
        errorAttributes.put("findType", exception.getFindType().name());
        errorAttributes.put("findValue", exception.getFindValue().toString());

        ErrorAttributeDto errorAttributeDTO = new ErrorAttributeDto(
                request.getRequestURI(),
                errorAttributes
        );

        ErrorResponseDto errorResponseDTO = ErrorResponseDto.create(
                AuthServerErrorCode.USER_NOT_FOUND,
                exception.getErrorCaption(),
                errorAttributeDTO
        );

        return new ResponseEntity<>(errorResponseDTO, HttpStatus.NOT_FOUND);
    }

    // Invalid Opaque Token
    @ExceptionHandler(InvalidOpaqueTokenException.class)
    public ResponseEntity<Object> handleInvalidOpaqueTokenException(
            InvalidOpaqueTokenException exception, HttpServletRequest request, HttpServletResponse response) {
        if (isHtmlRequest(request)) {
            Map<String, Object> variables = new HashMap<>();
            String htmlContent = htmlRenderingService.renderHtml(request, response, "error/400", variables);
            return new ResponseEntity<>(htmlContent, HttpStatus.BAD_REQUEST);
        }

        ErrorAttributeDto errorAttributeDTO = new ErrorAttributeDto(
                request.getRequestURI(),
                null
        );

        ErrorResponseDto errorResponseDTO = ErrorResponseDto.create(
                AuthServerErrorCode.INVALID_OPAQUE_TOKEN,
                "Invalid opaque token.",
                errorAttributeDTO
        );

        return new ResponseEntity<>(errorResponseDTO, HttpStatus.BAD_REQUEST);
    }

    // Invalid Access Token
    @ExceptionHandler(InvalidAccessTokenException.class)
    public ResponseEntity<Object> handleInvalidAccessTokenException(
            InvalidAccessTokenException exception, HttpServletRequest request, HttpServletResponse response) {
        if (isHtmlRequest(request)) {
            Map<String, Object> variables = new HashMap<>();
            String htmlContent = htmlRenderingService.renderHtml(request, response, "error/400", variables);
            return new ResponseEntity<>(htmlContent, HttpStatus.BAD_REQUEST);
        }

        ErrorAttributeDto errorAttributeDTO = new ErrorAttributeDto(
                request.getRequestURI(),
                null
        );

        ErrorResponseDto errorResponseDTO = ErrorResponseDto.create(
                AuthServerErrorCode.INVALID_ACCESS_TOKEN,
                "Invalid access token.",
                errorAttributeDTO
        );

        return new ResponseEntity<>(errorResponseDTO, HttpStatus.BAD_REQUEST);
    }

    // Global Exception
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleGlobalException(
            Exception exception, HttpServletRequest request, HttpServletResponse response) {
        log.error("Global Exception", exception);
        log.error("Request URI: {}", request.getRequestURI());

        if (isHtmlRequest(request)) {
            Map<String, Object> variables = new HashMap<>();
            String htmlContent = htmlRenderingService.renderHtml(request, response, "error/500", variables);
            return new ResponseEntity<>(htmlContent, HttpStatus.INTERNAL_SERVER_ERROR);
        }

        ErrorAttributeDto errorAttributeDTO = new ErrorAttributeDto(
                request.getRequestURI(),
                null
        );

        ErrorResponseDto errorResponseDTO = ErrorResponseDto.create(
                AuthServerErrorCode.INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                errorAttributeDTO
        );

        return new ResponseEntity<>(errorResponseDTO, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}

