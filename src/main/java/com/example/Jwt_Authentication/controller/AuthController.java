package com.example.Jwt_Authentication.controller;

import com.example.Jwt_Authentication.config.UserClient;
import com.example.Jwt_Authentication.model.AppUser;
import com.example.Jwt_Authentication.model.dtos.AuthRequest;
import com.example.Jwt_Authentication.model.dtos.AuthResponse;
import com.example.Jwt_Authentication.model.dtos.RefreshRequest;
import com.example.Jwt_Authentication.model.dtos.UserDto;
import com.example.Jwt_Authentication.repository.AppUserRepository;
import com.example.Jwt_Authentication.service.JwtService;
import com.example.Jwt_Authentication.service.TokenCacheService;
import io.jsonwebtoken.JwtException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;


@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final TokenCacheService tokenCacheService;
    private final UserClient userClient;
    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthController(AuthenticationManager authenticationManager, TokenCacheService tokenCacheService, UserClient userClient, AppUserRepository appUserRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.authenticationManager = authenticationManager;
        this.tokenCacheService = tokenCacheService;
        this.userClient = userClient;
        this.appUserRepository = appUserRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody AuthRequest request){
        if(appUserRepository.findByUsername(request.email()).isPresent()){
            return ResponseEntity.status(HttpStatus.CONFLICT).body("user exists");
        }
        AppUser user = new AppUser();
        user.setUsername(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setRoles("USER_ROLE");
        appUserRepository.save(user);
        return ResponseEntity.ok("Registered Successfully");
    }
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody AuthRequest request) {
        try {
            // Call user-service to validate email/password
            UserDto user = userClient.validateUser(request.email(), request.password());

            // If valid → generate tokens
            String access = jwtService.generateAccessToken(user.getEmail());
            String refresh = jwtService.generateRefreshToken(user.getEmail());

            // Store in cache
            tokenCacheService.storeTokens(user.getEmail(), access, refresh, jwtService.getAccessTokenValidityMs());

            return ResponseEntity.ok(new AuthResponse(access, refresh));
        } catch (Exception ex) {
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
