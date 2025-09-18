package com.example.Jwt_Authentication.service;

import com.example.Jwt_Authentication.model.AppUser;
import com.example.Jwt_Authentication.repository.AppUserRepository;
import org.springframework.stereotype.Service;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final AppUserRepository appUserRepository;

    public CustomUserDetailsService(AppUserRepository appUserRepository) {
        this.appUserRepository = appUserRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser user = appUserRepository.findByUsername(username).orElseThrow(
                () -> new UsernameNotFoundException("User not found with username: "+username));
        return User.withUsername(username)
                .password(user.getPassword())
                .authorities(user.getRoles().split(",")).build();
    }
}
