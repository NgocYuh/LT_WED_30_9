package com.ngocyuh.jwt.dto;

public record LoginResponse(String token, long expiresIn) {}
