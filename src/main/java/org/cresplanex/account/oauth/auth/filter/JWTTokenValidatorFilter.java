package org.cresplanex.account.oauth.auth.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.cresplanex.account.oauth.constants.JwtSettings;
import org.cresplanex.account.oauth.exception.InvalidAccessTokenException;
import org.springframework.core.env.Environment;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
public class JWTTokenValidatorFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {
       String header = request.getHeader(JwtSettings.JWT_HEADER);
       if (header != null && header.startsWith("Bearer ")) {
           try {
               String token = header.substring(7);
               Environment env = getEnvironment();
               String secret = env.getProperty(JwtSettings.JWT_SECRET_KEY,
                       JwtSettings.JWT_SECRET_DEFAULT_VALUE);
               SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
               Claims claims = Jwts.parser().verifyWith(secretKey)
                       .build().parseSignedClaims(token).getPayload();
               String username = String.valueOf(claims.get("email"));
               String authorities = String.valueOf(claims.get("authorities"));
               Authentication authentication = new UsernamePasswordAuthenticationToken(username, null,
                       AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
               SecurityContextHolder.getContext().setAuthentication(authentication);
           } catch (Exception exception) {
               SecurityContextHolder.getContext().setAuthentication(null);
           }
       }
       filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getServletPath().equals("/api/auth/login");
    }

}
