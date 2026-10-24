package com.fyntriva.fyntriva_bff.auth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
public class SecurityConfig {

    private static final RequestMatcher SIGNUP_POST = (HttpServletRequest request) ->
            HttpMethod.POST.matches(request.getMethod())
                    && "/api/signup".equals(request.getServletPath());

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.ignoringRequestMatchers(SIGNUP_POST))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.POST, "/api/signup").permitAll()
                        .anyRequest().authenticated()
                );

        return http.build();
    }
}
