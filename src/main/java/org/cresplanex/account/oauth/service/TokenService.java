package org.cresplanex.account.oauth.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.cresplanex.account.oauth.constants.JwtSettings;
import org.cresplanex.account.oauth.utils.SecureOpaqueTokenGenerator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service
@Transactional
public class TokenService {
    private final Environment env;

    @Value("${jwt.token.issuer}")
    public String JWT_TOKEN_ISSUER;

    @Value("${jwt.token.subject}")
    public String JWT_TOKEN_SUBJECT;

    @Value("${jwt.token.expiration}")
    public String JWT_TOKEN_EXPIRATION;

    public String generateJwtToken(Authentication authentication) {
        if (null != env) {
            long expirationTimeInMillis = JwtSettings.JWT_TOKEN_DEFAULT_EXPIRATION;

            if (JWT_TOKEN_EXPIRATION != null) {
                try{
                    expirationTimeInMillis = Long.parseLong(JWT_TOKEN_EXPIRATION);
                }catch(NumberFormatException ignored){
                }
            }

            String issuer = JWT_TOKEN_ISSUER;
            if (issuer == null) {
                issuer = JwtSettings.JWT_TOKEN_DEFAULT_ISSUER;
            }

            String subject = JWT_TOKEN_SUBJECT;
            if (subject == null) {
                subject = JwtSettings.JWT_TOKEN_DEFAULT_SUBJECT;
            }

            String secret = env.getProperty(
                    JwtSettings.JWT_SECRET_KEY,
                    JwtSettings.JWT_SECRET_DEFAULT_VALUE
            );
            SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
            return Jwts.builder()
                    .issuer(issuer)
                    .subject(subject)
                    .claim("email", authentication.getName())
                    .claim("authorities", authentication.getAuthorities().stream().map(
                            GrantedAuthority::getAuthority).collect(Collectors.joining(",")))
                    .issuedAt(new java.util.Date())
                    .expiration(new java.util.Date((new java.util.Date()).getTime() + expirationTimeInMillis))
                    .signWith(secretKey).compact();
        }

        return null;
    }

    public String generateOpaqueToken() {
        return SecureOpaqueTokenGenerator.generateToken();
    }
}
