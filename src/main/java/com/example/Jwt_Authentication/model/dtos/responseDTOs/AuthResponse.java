package com.example.Jwt_Authentication.model.dtos.responseDTOs;

import com.example.Jwt_Authentication.model.enums.Roles;

public record AuthResponse(String accessToken, String refreshToken, Roles role) {
}
