package com.ograh.sessionauth.auth.dtos;

import lombok.Data;

@Data
public class MeResponse {
    private String id;
    private String email;
    private String createdAt;
}
