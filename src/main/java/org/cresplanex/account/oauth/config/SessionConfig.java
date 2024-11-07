package org.cresplanex.account.oauth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

@Configuration
@EnableRedisHttpSession // Redisを使用したHTTPセッションを有効化
public class SessionConfig {
}
