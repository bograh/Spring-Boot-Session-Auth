package com.ograh.sessionauth.auth.dtos;

import lombok.Data;
import org.springframework.http.ResponseCookie;

@Data
public class CookieHeaders {
    private ResponseCookie sessionCookie;
    private ResponseCookie refreshCookie;
    private ResponseCookie ipAddressCookie;
}
