package com.ngocyuh.jwt.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

@Service
public class JwtService {
    private final byte[] secretBytes;
    private final long expirationMs;
    private final Clock clock;

    public JwtService(@Value("${security.jwt.secret-key}") String secret,
                      @Value("${security.jwt.expiration-ms}") long expirationMs) {
        try {
            this.secretBytes = Base64.getDecoder().decode(secret);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("JWT secret must be valid Base64", exception);
        }
        if (secretBytes.length < 32) {
            throw new IllegalArgumentException("JWT secret must decode to at least 32 bytes for HS256");
        }
        if (expirationMs <= 0) {
            throw new IllegalArgumentException("JWT expiration must be greater than zero milliseconds");
        }
        this.expirationMs = expirationMs;
        this.clock = Clock.systemUTC();
    }

    public String generateToken(UserDetails userDetails) {
        Instant issuedAt = clock.instant();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(userDetails.getUsername())
                .claim("authorities", userDetails.getAuthorities().stream().map(Object::toString).toList())
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(issuedAt.plusMillis(expirationMs)))
                .build();
        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).build(), claims);
        try {
            signedJwt.sign(new MACSigner(secretBytes));
            return signedJwt.serialize();
        } catch (JOSEException exception) {
            throw new IllegalStateException("Could not sign JWT", exception);
        }
    }

    public String extractUsername(String token) {
        return parseAndValidate(token).getSubject();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        JWTClaimsSet claims = parseAndValidate(token);
        return userDetails.getUsername().equalsIgnoreCase(claims.getSubject());
    }

    public long getExpirationMs() {
        return expirationMs;
    }

    private JWTClaimsSet parseAndValidate(String token) {
        try {
            SignedJWT signedJwt = SignedJWT.parse(token);
            if (!JWSAlgorithm.HS256.equals(signedJwt.getHeader().getAlgorithm())) {
                throw new BadCredentialsException("JWT algorithm is not allowed");
            }
            if (!signedJwt.verify(new MACVerifier(secretBytes))) {
                throw new BadCredentialsException("JWT signature is invalid");
            }

            JWTClaimsSet claims = signedJwt.getJWTClaimsSet();
            Date expiration = claims.getExpirationTime();
            if (expiration == null || !expiration.after(Date.from(clock.instant()))) {
                throw new CredentialsExpiredException("JWT has expired");
            }
            if (claims.getSubject() == null || claims.getSubject().isBlank()) {
                throw new BadCredentialsException("JWT subject is missing");
            }
            return claims;
        } catch (ParseException | JOSEException exception) {
            throw new BadCredentialsException("JWT is invalid", exception);
        }
    }
}
