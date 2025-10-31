package com.ograh.sessionauth.auth;

import com.ograh.sessionauth.auth.dtos.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

//@CrossOrigin(origins = "http://localhost:5173", allowCredentials = "true")
@RequiredArgsConstructor
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody AuthRequest authRequest) {
        AuthResponse response = authService.register(authRequest);
        if (!response.getRefreshToken().matches("^[A-Za-z0-9-_.]+$")) {
            throw new IllegalArgumentException("Invalid token format");
        }

        // Safe: token is a server-generated Base64URL JWT string, cannot contain script characters.
        ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", response.getRefreshToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("None")
                .maxAge(Duration.ofDays(7))
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .header(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, HttpHeaders.SET_COOKIE)
                .body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest authRequest) {
        AuthResponse response = authService.login(authRequest);
        String sessionId = authService.generateSessionId(response);

        /*if (!response.getRefreshToken().matches("^[A-Za-z0-9-_.]+$")) {
            throw new IllegalArgumentException("Invalid token format");
        }*/

        CookieHeaders cookieHeaders = authService.setCookies(response.getRefreshToken(), sessionId, null);


        return ResponseEntity.ok()
                /*.header(HttpHeaders.SET_COOKIE, cookieHeaders.getRefreshCookie().toString())*/
                .header(HttpHeaders.SET_COOKIE, cookieHeaders.getSessionCookie().toString())
                .header(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, HttpHeaders.SET_COOKIE)
                .body(response);
    }

    @GetMapping("/me")
    public ResponseEntity<MeResponse> me(HttpServletRequest request) {
        MeResponse response = authService.getMe(request);
        return ResponseEntity.ok(response);
    }




}
