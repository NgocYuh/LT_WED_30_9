package com.ngocyuh.jwt.controller;

import com.ngocyuh.jwt.dto.LoginRequest;
import com.ngocyuh.jwt.dto.LoginResponse;
import com.ngocyuh.jwt.dto.RegisterRequest;
import com.ngocyuh.jwt.dto.UserResponse;
import com.ngocyuh.jwt.entity.User;
import com.ngocyuh.jwt.service.AuthenticationService;
import com.ngocyuh.jwt.service.JwtService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {
    private final AuthenticationService authenticationService;
    private final JwtService jwtService;

    public AuthenticationController(AuthenticationService authenticationService, JwtService jwtService) {
        this.authenticationService = authenticationService;
        this.jwtService = jwtService;
    }

    @PostMapping("/signup")
    public ResponseEntity<UserResponse> signup(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(UserResponse.from(authenticationService.signup(request)));
    }

    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest request) {
        User user = authenticationService.authenticate(request);
        return new LoginResponse(jwtService.generateToken(user), jwtService.getExpirationMs());
    }
}
