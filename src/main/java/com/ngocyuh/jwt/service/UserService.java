package com.ngocyuh.jwt.service;

import com.ngocyuh.jwt.dto.UserResponse;
import com.ngocyuh.jwt.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Transactional(readOnly = true)
    public List<UserResponse> allUsers() {
        return userRepository.findAll().stream().map(UserResponse::from).toList();
    }
}
