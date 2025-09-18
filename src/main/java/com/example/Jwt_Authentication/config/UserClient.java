package com.example.Jwt_Authentication.config;

import com.example.Jwt_Authentication.model.dtos.AuthRequest;
import com.example.Jwt_Authentication.model.dtos.UserDto;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class UserClient {

    private final RestTemplate restTemplate;

    public UserClient(RestTemplateBuilder builder) {
        this.restTemplate = builder.build();
    }

    public UserDto validateUser(String email, String password) {
        String url = "http://user-service/api/users/validate"; // endpoint in user-service
        AuthRequest req = new AuthRequest(email, password);
        return restTemplate.postForObject(url, req, UserDto.class);
    }
}