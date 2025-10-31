package com.ograh.sessionauth.auth.dtos;

import lombok.Data;

@Data
public class AuthResponse {
    private UserResponse user;
    private String token;
    private String refreshToken;
    private boolean success;

    @Data
    public static class UserResponse {
        private String id;
        private String email;
    }
}
