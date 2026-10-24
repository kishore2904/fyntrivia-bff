package com.fyntriva.fyntriva_bff.service;

import com.fyntriva.fyntriva_bff.dto.SignupRequest;
import com.fyntriva.fyntriva_bff.entity.User;
import com.fyntriva.fyntriva_bff.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;

@Service
public class SignupService {

    private static final int MAX_PASSWORD_BYTES = 72;

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public SignupService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User signup(SignupRequest request) {
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Signup details are required");
        }
        String firstName = request.firstName();
        String lastName = request.lastName();
        String email = request.email();
        String password = request.password();
        validate(firstName, lastName, email, password);

        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);
        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email is already registered");
        }

        User user = new User(
                firstName.trim(),
                lastName.trim(),
                normalizedEmail,
                passwordEncoder.encode(password)
        );
        return userRepository.saveAndFlush(user);
    }

    public List<User> getUsers() {
        return userRepository.findAll();
    }

    public User getUser(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    }

    private void validate(String firstName, String lastName, String email, String password) {
        if (isBlank(firstName) || isBlank(lastName) || isBlank(email) || isBlank(password)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "All signup fields are required");
        }
        if (firstName.trim().length() > 50
                || lastName.trim().length() > 50
                || email.trim().length() > 254
                || password.getBytes(StandardCharsets.UTF_8).length > MAX_PASSWORD_BYTES
                || !email.trim().matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Signup fields have invalid values");
        }
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
