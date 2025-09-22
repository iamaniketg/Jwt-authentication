package com.example.Jwt_Authentication.controller;

import com.example.Jwt_Authentication.config.UserClient;
import com.example.Jwt_Authentication.model.dtos.AuthRequest;
import com.example.Jwt_Authentication.model.dtos.AuthResponse;
import com.example.Jwt_Authentication.model.dtos.RefreshRequest;
import com.example.Jwt_Authentication.model.dtos.UserDto;
import com.example.Jwt_Authentication.service.JwtService;
import com.example.Jwt_Authentication.service.TokenCacheService;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Slf4j
@RestController
@RequestMapping("/auth")
public class AuthController {
    private final TokenCacheService tokenCacheService;
    private final UserClient userClient;
    private final JwtService jwtService;
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    public AuthController(TokenCacheService tokenCacheService, UserClient userClient, JwtService jwtService) {
        this.tokenCacheService = tokenCacheService;
        this.userClient = userClient;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody AuthRequest request){
        // Registration should be handled by User-service
        // For now, we'll just redirect or handle it appropriately
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED).body("Registration should be handled by User-service");
    }
    
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody AuthRequest request) {
        try {
            log.info("request body in auth service {}", request);
            // Call user-service to validate email/password
            UserDto user = userClient.validateUser(request.email(), request.password());

            // If valid → generate tokens
            String access = jwtService.generateAccessToken(user.getEmail());
            String refresh = jwtService.generateRefreshToken(user.getEmail());

            // Store in cache
            tokenCacheService.storeTokens(user.getEmail(), access, refresh, jwtService.getAccessTokenValidityMs());

            return ResponseEntity.ok(new AuthResponse(access, refresh));
        } catch (Exception ex) {
            logger.error("Error during login: ", ex);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest refreshRequest){
        try {
            String refresh = refreshRequest.refreshToken();
            String userName = jwtService.extractUserName(refresh);
            if(!jwtService.isTokenValid(refresh,userName)){
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Refresh token");
            }
            String newAccess = jwtService.generateAccessToken(userName);
            String newRefresh = jwtService.generateRefreshToken(userName);
            return ResponseEntity.ok(new AuthResponse(newAccess,newRefresh));
        }catch(JwtException | IllegalArgumentException ex){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
        }
    }
}
