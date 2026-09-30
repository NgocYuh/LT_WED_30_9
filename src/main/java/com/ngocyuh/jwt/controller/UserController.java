package com.ngocyuh.jwt.controller;

import com.ngocyuh.jwt.dto.UserResponse;
import com.ngocyuh.jwt.entity.User;
import com.ngocyuh.jwt.service.UserService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/me")
    public UserResponse me(@AuthenticationPrincipal User user) {
        return UserResponse.from(user);
    }

    @GetMapping
    public List<UserResponse> allUsers() {
        return userService.allUsers();
    }
}
