package com.example.Jwt_Authentication.config;

import com.example.Jwt_Authentication.model.dtos.requestDTOS.AuthRequest;
import com.example.Jwt_Authentication.model.dtos.UserDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class UserClient {

    @Autowired
    private RestTemplate restTemplate;

    public UserDto validateUser(String email, String password) {
        String url = "http://user-service:8081/api/users/validate";

        AuthRequest req = new AuthRequest(email, password);
        return restTemplate.postForObject(url, req, UserDto.class);
    }
}