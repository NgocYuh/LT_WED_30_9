package com.ngocyuh.jwt.dto;

import com.ngocyuh.jwt.entity.User;

import java.time.Instant;

public record UserResponse(Long id, String fullName, String email, String role, Instant createdAt) {
    public static UserResponse from(User user) {
        return new UserResponse(user.getId(), user.getFullName(), user.getEmail(), user.getRole().name(), user.getCreatedAt());
    }
}
