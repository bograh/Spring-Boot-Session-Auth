package com.ograh.sessionauth.security;

import com.ograh.sessionauth.auth.User;
import com.ograh.sessionauth.auth.UserRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
@RequiredArgsConstructor
public class JwtService {

    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    private final UserRepository userRepository;

    @Value("${security.jwt.secret-key}")
    private String tokenSecret;

    public String generatePasswordResetToken(String email) {
        User user = userRepository.findByEmail(email).orElseThrow(
                () -> new RuntimeException("User not found")
        );
        String userId = user.getId();
        Date now = new Date();
        long tokenExpiration = 900000;
        Date expiration = new Date(now.getTime() + tokenExpiration);

        return Jwts.builder()
                .subject(email)
                .issuedAt(now)
                .expiration(expiration)
                .claim("user_id", userId)
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(tokenSecret)))
                .compact();
    }

    public String generateToken(Authentication authentication) {
        String email = authentication.getName();
        String user_id;
        user_id = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"))
                .getId();
        Date now = new Date();
        long tokenExpiration = 5400000;
        Date expiration = new Date(now.getTime() + tokenExpiration);

        return Jwts.builder()
                .subject(email)
                .issuedAt(now)
                .expiration(expiration)
                .claim("user_id", user_id)
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(tokenSecret)))
                .compact();
    }

    public String generateRefreshToken(Authentication authentication) {
        String email = authentication.getName();
        String user_id;
        user_id = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"))
                        .getId();
        Date now = new Date();
        long refreshTokenExpiration = 7776000000L;
        Date expiration = new Date(now.getTime() + refreshTokenExpiration);

        return Jwts.builder()
                .subject(email)
                .issuedAt(now)
                .expiration(expiration)
                .claim("user_id", user_id)
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(tokenSecret)))
                .compact();
    }

    public String getEmailFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(tokenSecret)))
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return claims.getSubject();
    }

    public String getUserIdFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(tokenSecret)))
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return claims.get("user_id", String.class);
    }

    // validate Jwt token
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(tokenSecret)))
                .build()
                .parseSignedClaims(token)
                .getPayload();

            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
            throw new RuntimeException("Invalid JWT token");
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
            throw new RuntimeException("JWT token is expired");
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
            throw new RuntimeException("JWT token is unsupported");
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
            throw new RuntimeException("JWT claims string is empty");
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }

}