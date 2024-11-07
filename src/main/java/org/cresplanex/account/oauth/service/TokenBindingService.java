package org.cresplanex.account.oauth.service;

import lombok.AllArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@AllArgsConstructor
@Service
public class TokenBindingService {

    private final StringRedisTemplate redisTemplate;

    public void bindTokens(String opaqueToken, String jwtToken, long expirationTimeInMillis) {
        // RedisにOpaqueトークンとJWTを保存
        redisTemplate.opsForValue().set(opaqueToken, jwtToken, expirationTimeInMillis, TimeUnit.SECONDS);
    }

    public String getJwtToken(String opaqueToken) {
        // RedisからJWTを取得
        return redisTemplate.opsForValue().get(opaqueToken);
    }

    public void removeToken(String opaqueToken) {
        // Redisからトークンを削除
        redisTemplate.delete(opaqueToken);
    }
}
