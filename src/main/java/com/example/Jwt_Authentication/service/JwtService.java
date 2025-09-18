package com.example.Jwt_Authentication.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {
    private final Key signingKey;
    @Getter
    private final long accessTokenValidityMs;
    private final long refreshTokenValidityMs;

    public JwtService(@Value("${jwt.base64-secret}") String base64Secret,
                      @Value("${jwt.access-token-validity-minutes}") long accessMinutes,
                      @Value("${jwt.refresh-token-validity-days}") long refreshDays) {
        byte[] keyBytes = Decoders.BASE64.decode(base64Secret);
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
        this.accessTokenValidityMs = accessMinutes * 60 * 1000;
        this.refreshTokenValidityMs = refreshDays * 24 * 60 * 60 * 1000;
    }
    public String generateAccessToken(String userName){
        return buildToken(userName, accessTokenValidityMs);
    }
    public String generateRefreshToken(String userName){
        return buildToken(userName, refreshTokenValidityMs);
    }
    public String buildToken(String subject, long validityMs){
        long now = System.currentTimeMillis();
        return Jwts.builder().setSubject(subject)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now+validityMs))
                .signWith(signingKey)
                .compact();
    }
    public boolean isTokenValid(String token,String username){
        final String subject = extractUserName(token);
        return subject.equals(username) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String extractUserName(String token){
        return extractClaims(token, Claims::getSubject);
    }
    public Date extractExpiration(String token){
        return extractClaims(token, Claims::getExpiration);
    }
    public <T> T extractClaims(String token, Function<Claims, T> claimsTFunction){
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claimsTFunction.apply(claims);
    }


}

