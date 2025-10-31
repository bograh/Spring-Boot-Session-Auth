package com.ograh.sessionauth.auth;

import com.ograh.sessionauth.auth.dtos.*;
import com.ograh.sessionauth.security.JwtService;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.BadRequestException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@RequiredArgsConstructor
@Service
public class AuthService {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final RedisTemplate<String, String> redisTemplate;

    public AuthResponse register(AuthRequest authRequest) {
        String email = authRequest.getEmail().trim();

        try {
            if (userRepository.existsByEmail(email)) {
                throw new BadRequestException("Email is already in use");
            }

            User user = new User();
            user.setEmail(email);
            user.setPassword(passwordEncoder.encode(authRequest.getPassword()));
            userRepository.save(user);

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, authRequest.getPassword())
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String token = jwtService.generateToken(authentication);
            String refreshToken = jwtService.generateRefreshToken(authentication);

            return createAuthResponse(user, token, refreshToken);

        } catch (Exception ex) {
            throw new RuntimeException("Invalid Username or Password");
        }
    }

    public AuthResponse login(AuthRequest authRequest) {
        String email = authRequest.getEmail();

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, authRequest.getPassword())
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String token = jwtService.generateToken(authentication);
            String refreshToken = jwtService.generateRefreshToken(authentication);
            User user = userRepository.findByEmail(email).orElseThrow(
                    () -> new RuntimeException("Incorrect email or password")
            );

            return createAuthResponse(user, token, refreshToken);

        } catch (Exception ex) {
            throw new RuntimeException("Invalid Username or Password");
        }
    }

    public MeResponse getMe(HttpServletRequest request) {
        List<String> cookieVals = new ArrayList<>();

        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (CookieName.SESSION_ID.name().equals(cookie.getName())) {
                    cookieVals.add(cookie.getValue());
                    break;
                }
            }
        }
        if (cookieVals.isEmpty()) {
            throw new RuntimeException("Session not found in cookies");
        }

        String token = redisTemplate.opsForValue().get(cookieVals.get(0));
        if (token == null) {
            throw new RuntimeException("Session expired or not found in Redis");
        }

        String email = jwtService.getEmailFromToken(token);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        MeResponse response = new MeResponse();
        response.setId(user.getId());
        response.setEmail(user.getEmail());
        response.setCreatedAt(user.getCreatedAt().toString());
        return response;
    }

    public String generateSessionId(AuthResponse response) {
        String sessionId = genSecureId();

        redisTemplate.opsForValue().set(sessionId, response.getRefreshToken(), Duration.ofDays(7));
        return sessionId;
    }

    public CookieHeaders setCookies(
            String refreshToken, String sessionId, @Nullable String ipAddress
    ) {
        ResponseCookie refreshCookie = ResponseCookie.from(CookieName.REFRESH_TOKEN.name(), refreshToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("None")
                .maxAge(Duration.ofDays(7))
                .build();

        ResponseCookie sessionIdCookie = ResponseCookie.from(CookieName.SESSION_ID.name(), sessionId)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("None")
                .maxAge(Duration.ofDays(7))
                .build();

        CookieHeaders cookieHeaders = new CookieHeaders();
        cookieHeaders.setSessionCookie(sessionIdCookie);
        cookieHeaders.setRefreshCookie(refreshCookie);
        return cookieHeaders;
    }

    private static String genSecureId() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[24];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private AuthResponse createAuthResponse(User user, String token, String refreshToken) {
        AuthResponse response = new AuthResponse();
        response.setToken(token);
        response.setRefreshToken(refreshToken);
        response.setSuccess(true);
        AuthResponse.UserResponse userResponse = new AuthResponse.UserResponse();
        userResponse.setId(user.getId());
        userResponse.setEmail(user.getEmail());
        response.setUser(userResponse);
        return response;
    }

}
