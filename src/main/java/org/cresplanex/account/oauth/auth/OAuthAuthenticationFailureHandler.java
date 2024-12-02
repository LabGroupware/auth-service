package org.cresplanex.account.oauth.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.cresplanex.account.oauth.constants.AuthServerErrorCode;
import org.cresplanex.account.oauth.dto.api.ErrorAttributeDto;
import org.cresplanex.account.oauth.dto.api.ErrorResponseDto;
import org.cresplanex.account.oauth.service.HtmlRenderingService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@Component
public class OAuthAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HtmlRenderingService htmlRenderingService;

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception
    ) throws IOException, ServletException {
        if (exception instanceof OAuth2AuthorizationCodeRequestAuthenticationException ex) { // 認可コードリクエスト中のエラー
            OAuth2AuthorizationCodeRequestAuthenticationToken tokenReq = ex.getAuthorizationCodeRequestAuthentication();

            if (tokenReq != null) {
                String redirectUri = tokenReq.getRedirectUri();
                if (redirectUri != null) {
                    String redirectDestination = redirectUri + "?error=" + ex.getError().getErrorCode()
                            + "&error_description=" + ex.getError().getDescription() + "&error_uri=" + ex.getError().getUri();
                    response.sendRedirect(redirectDestination);
                    return;
                }
            }

            if (isHtmlRequest(request)) {
                Map<String, Object> variables = new HashMap<>();
                variables.put("errorDescription", ex.getError().getDescription());
                variables.put("errorCode", ex.getError().getErrorCode());
                variables.put("errorUri", ex.getError().getUri());
                String htmlContent = htmlRenderingService.renderHtml(request, response,"oauth-invalid", variables);
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.setContentType(MediaType.TEXT_HTML_VALUE);
                response.getWriter().write(htmlContent);
                return;
            }

            Map<String, Object> errorAttributes = new HashMap<>();
            errorAttributes.put("code", ex.getError().getErrorCode());
            errorAttributes.put("description", ex.getError().getDescription());
            errorAttributes.put("error_uri", ex.getError().getUri());

            ErrorAttributeDto errorAttributeDTO = new ErrorAttributeDto(
                    request.getRequestURI(),
                    errorAttributes
            );

            ErrorResponseDto errorResponseDTO = ErrorResponseDto.create(
                    AuthServerErrorCode.OAUTH2_CODE_REQUEST_FAILED,
                    "OAuth2 code request failed",
                    errorAttributeDTO
            );
            String jsonResponse = objectMapper.writeValueAsString(errorResponseDTO);

            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(jsonResponse);

            return;
        }

        if (isHtmlRequest(request)) {
            Map<String, Object> variables = new HashMap<>();
            String htmlContent = htmlRenderingService.renderHtml(request, response, "error/401", variables);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.TEXT_HTML_VALUE);
            response.getWriter().write(htmlContent);
            return;
        }

        // その他のエラー
        Map<String, Object> errorAttributes = new HashMap<>();
        errorAttributes.put("error", HttpStatus.UNAUTHORIZED.getReasonPhrase());

        ErrorAttributeDto errorAttributeDTO = new ErrorAttributeDto(
                request.getRequestURI(),
                errorAttributes
        );

        ErrorResponseDto errorResponseDTO = ErrorResponseDto.create(
                AuthServerErrorCode.AUTHENTICATION_FAILED,
                "Authentication failed",
                errorAttributeDTO
        );
        String jsonResponse = objectMapper.writeValueAsString(errorResponseDTO);

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(jsonResponse);
    }

    private boolean isHtmlRequest(HttpServletRequest request) {
        String acceptHeader = request.getHeader("Accept");

        return acceptHeader != null && acceptHeader.contains("text/html");
    }
}
