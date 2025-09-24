package com.example.Jwt_Authentication.service;

import com.example.Jwt_Authentication.model.dtos.UserDto;
import com.example.Jwt_Authentication.model.enums.Roles;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class TokenCacheService {

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    public void storeTokens(String email, String accessToken, String refreshToken, Roles role, long expiry) {
        redisTemplate.opsForValue().set("ACCESS:" + email, accessToken, expiry, TimeUnit.MILLISECONDS);
        redisTemplate.opsForValue().set("REFRESH:" + email, refreshToken, expiry * 2, TimeUnit.MILLISECONDS);
        redisTemplate.opsForValue().set("ROLE:" + email, role.name(), expiry * 2, TimeUnit.MILLISECONDS); // ✅ store role
    }


    public String getAccessToken(String email) {
        return redisTemplate.opsForValue().get("ACCESS:" + email);
    }

    public String getRefreshToken(String email) {
        return redisTemplate.opsForValue().get("REFRESH:" + email);
    }

    public Roles getRoleByEmail(String email) {
        String roleStr = redisTemplate.opsForValue().get("ROLE:" + email);
        return roleStr != null ? Roles.valueOf(roleStr) : null;
    }


}

