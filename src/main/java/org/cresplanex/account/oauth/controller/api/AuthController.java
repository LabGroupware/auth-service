package org.cresplanex.account.oauth.controller.api;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.cresplanex.account.oauth.constants.AuthServerErrorCode;
import org.cresplanex.account.oauth.constants.JwtSettings;
import org.cresplanex.account.oauth.dto.api.ResponseDto;
import org.cresplanex.account.oauth.dto.api.auth.LoginRequestDto;
import org.cresplanex.account.oauth.dto.api.auth.TokenResponseDto;
import org.cresplanex.account.oauth.exception.InvalidOpaqueTokenException;
import org.cresplanex.account.oauth.service.TokenBindingService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final TokenBindingService tokenBindingService;

    @Value("${jwt.token.expiration}")
    public String JWT_TOKEN_EXPIRATION;

    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public ResponseEntity<ResponseDto<TokenResponseDto>> login(
            @Valid @RequestBody LoginRequestDto dto
    ) {
        String opaqueToken = dto.getOpaqueToken();
        String jwtToken = tokenBindingService.getJwtToken(opaqueToken);

        TokenResponseDto tokenResponseDto = getTokenResponseDto(jwtToken);

        ResponseDto<TokenResponseDto> response = new ResponseDto<>();
        response.setData(tokenResponseDto);
        response.setCode(AuthServerErrorCode.SUCCESS);
        response.setCaption("Login successful.");

        return ResponseEntity.ok(response);
    }

    private TokenResponseDto getTokenResponseDto(String jwtToken) {
        if (jwtToken == null) {
            throw new InvalidOpaqueTokenException("Invalid opaque token.");
        }

        long expirationTimeInMillis = JwtSettings.JWT_TOKEN_DEFAULT_EXPIRATION;

        if (JWT_TOKEN_EXPIRATION != null) {
            try{
                expirationTimeInMillis = Long.parseLong(JWT_TOKEN_EXPIRATION);
            }catch(NumberFormatException ignored){
            }
        }

        TokenResponseDto tokenResponseDto = new TokenResponseDto();
        tokenResponseDto.setAccessToken(jwtToken);
        tokenResponseDto.setExpiresIn(expirationTimeInMillis);
        return tokenResponseDto;
    }
}
