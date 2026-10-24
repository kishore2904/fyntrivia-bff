package com.fyntriva.fyntriva_bff.controller;

import com.fyntriva.fyntriva_bff.dto.SignupRequest;
import com.fyntriva.fyntriva_bff.dto.UserResponse;
import com.fyntriva.fyntriva_bff.entity.User;
import com.fyntriva.fyntriva_bff.service.SignupService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RestController
@RequestMapping("/api/signup")
public class SignupController {

    private final SignupService signupService;

    public SignupController(SignupService signupService) {
        this.signupService = signupService;
    }

    @PostMapping
    public ResponseEntity<UserResponse> signup(@RequestBody SignupRequest request) {
        User savedUser = signupService.signup(request);
        URI location = ServletUriComponentsBuilder.fromCurrentRequest()
                .path("/{id}")
                .buildAndExpand(savedUser.getId())
                .toUri();

        return ResponseEntity.created(location).body(UserResponse.from(savedUser));
    }

    @GetMapping
    public List<UserResponse> getUsers() {
        return signupService.getUsers().stream()
                .map(UserResponse::from)
                .toList();
    }

    @GetMapping("/{id}")
    public UserResponse getUser(@PathVariable Long id) {
        User user = signupService.getUser(id);
        return UserResponse.from(user);
    }

}
