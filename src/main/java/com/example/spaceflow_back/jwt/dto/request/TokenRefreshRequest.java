package com.example.spaceflow_back.jwt.dto.request;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class TokenRefreshRequest {

    // 만료된 Access Token 대신 클라이언트가 보낸 Refresh Token 문자열
    private String refreshToken;
}
