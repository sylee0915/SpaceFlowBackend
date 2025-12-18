package com.jwt.dto.response;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class TokenRefreshResponse {

    private String tokenType;

    // 새로 발급된 Access Token
    private String accessToken;

    // 새로 발급된 Access Token의 만료 시간 (밀리초)
    private Long accessTokenExpiresIn;

    // Refresh Token 자체는 변경되지 않을 수 있으나, 만료 시간을 갱신하거나
    // rotation 정책을 쓴다면 포함할 수 있습니다. 여기서는 필수 요소는 아님.
}
