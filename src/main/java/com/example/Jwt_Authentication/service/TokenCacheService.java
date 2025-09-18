package com.example.Jwt_Authentication.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class TokenCacheService {

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    public void storeTokens(String email, String accessToken, String refreshToken, long expiry) {
        redisTemplate.opsForValue().set("ACCESS:" + email, accessToken, expiry, TimeUnit.MILLISECONDS);
        redisTemplate.opsForValue().set("REFRESH:" + email, refreshToken, expiry * 2, TimeUnit.MILLISECONDS);
    }

    public String getAccessToken(String email) {
        return redisTemplate.opsForValue().get("ACCESS:" + email);
    }

    public String getRefreshToken(String email) {
        return redisTemplate.opsForValue().get("REFRESH:" + email);
    }
}

