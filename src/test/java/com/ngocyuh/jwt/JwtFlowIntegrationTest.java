package com.ngocyuh.jwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.ngocyuh.jwt.entity.Role;
import com.ngocyuh.jwt.entity.User;
import com.ngocyuh.jwt.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class JwtFlowIntegrationTest {
    private static final String SECRET =
            "VGhpcy1pcy1hLXRlc3Qtc2VjcmV0LWtleS10aGF0LWlzLWF0LWxlYXN0LTMyLWJ5dGVzLWxvbmc=";

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired UserRepository userRepository;
    @Autowired PasswordEncoder passwordEncoder;

    @BeforeEach
    void clearUsers() {
        userRepository.deleteAll();
    }

    @Test
    void signupLoginAndBearerTokenFlowWorksWithoutLeakingPassword() throws Exception {
        String signupBody = """
                {"email":"student@example.com","password":"Password123!","fullName":"JWT Student"}
                """;
        String signupJson = mockMvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON).content(signupBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value("student@example.com"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andReturn().getResponse().getContentAsString();
        assertThat(signupJson).doesNotContain("$2a$").doesNotContain("$2b$");

        String token = login("student@example.com", "Password123!");

        mockMvc.perform(get("/users/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.fullName").value("JWT Student"))
                .andExpect(jsonPath("$.password").doesNotExist());

        mockMvc.perform(get("/users").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminCanListUsers() throws Exception {
        User admin = new User();
        admin.setEmail("admin@example.com");
        admin.setFullName("Administrator");
        admin.setPassword(passwordEncoder.encode("Password123!"));
        admin.setRole(Role.ADMIN);
        userRepository.save(admin);

        String token = login("admin@example.com", "Password123!");
        mockMvc.perform(get("/users").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].password").doesNotExist());
    }

    @Test
    void protectedEndpointRejectsMissingInvalidAndExpiredTokens() throws Exception {
        mockMvc.perform(get("/users/me"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/users/me").header("Authorization", "Bearer not-a-jwt"))
                .andExpect(status().isUnauthorized());

        String wrongSignature = signedToken(new byte[32], Instant.now().plusSeconds(60));
        mockMvc.perform(get("/users/me").header("Authorization", "Bearer " + wrongSignature))
                .andExpect(status().isUnauthorized());

        String wrongAlgorithm = signedToken(new byte[48], Instant.now().plusSeconds(60), JWSAlgorithm.HS384);
        mockMvc.perform(get("/users/me").header("Authorization", "Bearer " + wrongAlgorithm))
                .andExpect(status().isUnauthorized());

        String expired = signedToken(Base64.getDecoder().decode(SECRET), Instant.now().minusSeconds(60));
        mockMvc.perform(get("/users/me").header("Authorization", "Bearer " + expired))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void wrongPasswordReturnsUnauthorized() throws Exception {
        mockMvc.perform(post("/auth/signup").contentType(MediaType.APPLICATION_JSON).content("""
                {"email":"student@example.com","password":"Password123!","fullName":"JWT Student"}
                """));
        mockMvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content("""
                {"email":"student@example.com","password":"wrong-password"}
                """))
                .andExpect(status().isUnauthorized());
    }

    private String login(String email, String password) throws Exception {
        String response = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new Credentials(email, password))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.expiresIn").value(3600000))
                .andReturn().getResponse().getContentAsString();
        JsonNode json = objectMapper.readTree(response);
        return json.get("token").asText();
    }

    private String signedToken(byte[] secret, Instant expiration) throws Exception {
        return signedToken(secret, expiration, JWSAlgorithm.HS256);
    }

    private String signedToken(byte[] secret, Instant expiration, JWSAlgorithm algorithm) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("student@example.com")
                .issueTime(Date.from(expiration.minusSeconds(60)))
                .expirationTime(Date.from(expiration))
                .build();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(algorithm).type(JOSEObjectType.JWT).build(), claims);
        jwt.sign(new MACSigner(secret));
        return jwt.serialize();
    }

    private record Credentials(String email, String password) {}
}
