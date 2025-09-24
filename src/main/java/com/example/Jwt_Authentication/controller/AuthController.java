package com.example.Jwt_Authentication.controller;

import com.example.Jwt_Authentication.config.UserClient;
import com.example.Jwt_Authentication.model.dtos.requestDTOS.AuthRequest;
import com.example.Jwt_Authentication.model.dtos.responseDTOs.AuthResponse;
import com.example.Jwt_Authentication.model.dtos.requestDTOS.RefreshRequest;
import com.example.Jwt_Authentication.model.dtos.UserDto;
import com.example.Jwt_Authentication.model.enums.Roles;
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
@RequestMapping()
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

//    @PostMapping("/register")
//    public ResponseEntity<?> registerUser(@RequestBody AuthRequest request){
//        // Registration should be handled by User-service
//        // For now, we'll just redirect or handle it appropriately
//        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED).body("Registration should be handled by User-service");
//    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody AuthRequest request) {
        try {
            log.info("Login attempt for email: {}", request.email()); // Avoid logging password for security
            // Call user-service to validate email/password
            UserDto user = userClient.validateUser(request.email(), request.password());
            log.info("User validated successfully for email: {}", user.getEmail());
            Roles role = user.getRole();
            // If valid → generate tokens
            String access = jwtService.generateAccessToken(user.getEmail(), String.valueOf(role));
            log.debug("Generated access token for email: {}", user.getEmail());
            String refresh = jwtService.generateRefreshToken(user.getEmail(), String.valueOf(role));
            log.debug("Generated refresh token for email: {}", user.getEmail());

            // Store in cache
            tokenCacheService.storeTokens(user.getEmail(), access, refresh, role, jwtService.getAccessTokenValidityMs());
            log.info("Tokens stored in cache for email: {}", user.getEmail());

            return ResponseEntity.ok(new AuthResponse(access, refresh, role));
        } catch (Exception ex) {
            log.error("Error during login for email: {}", request.email(), ex);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest refreshRequest){
        try {
            String refresh = refreshRequest.refreshToken();
            log.info("Refresh token request received");
            String userName = jwtService.extractUserName(refresh);
            log.debug("Extracted username from refresh token: {}", userName);
            Roles role = tokenCacheService.getRoleByEmail(userName); // ✅ role comes from Redis
            log.debug("Retrieved role from cache: {}", role);

            if(!jwtService.isTokenValid(refresh, userName)){
                log.warn("Invalid refresh token for username: {}", userName);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Refresh token");
            }

            log.info("Refresh token validated for username: {}", userName);
            String newAccess = jwtService.generateAccessToken(userName, String.valueOf(role));
            log.debug("Generated new access token for username: {}", userName);
            String newRefresh = jwtService.generateRefreshToken(userName, String.valueOf(role));
            log.debug("Generated new refresh token for username: {}", userName);

            return ResponseEntity.ok(new AuthResponse(newAccess, newRefresh, role));
        } catch(JwtException | IllegalArgumentException ex){
            log.error("Error during token refresh", ex);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
        }
    }

}
