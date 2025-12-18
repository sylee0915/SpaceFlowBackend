package com.jwt.dto.response;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class LoginResponse {

    // JWT 인증 타입 (예: Bearer)
    private String tokenType;

    // 실제 API 접근에 사용되는 Access Token
    private String accessToken;

    // Access Token이 만료되었을 때 갱신에 사용되는 Refresh Token
    private String refreshToken;

    // Access Token 만료 시간 (밀리초)
    private Long accessTokenExpiresIn;
}
