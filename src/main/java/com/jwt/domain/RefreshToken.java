package com.jwt.domain;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "refresh_token_id")
    private Long id;

    // RefreshToken의 키(실제 토큰 문자열)
    @Column(nullable = false, unique = true, length = 500)
    private String token;

    // 해당 토큰이 속한 사용자 ID (또는 User 엔티티와 OneToOne 매핑)
    @Column(nullable = false)
    private Long userId;

    /**
     * 토큰 값 업데이트 메서드 (토큰 재발급 시 사용)
     * @param newToken 새로 발급된 토큰 문자열
     */
    public void updateToken(String newToken) {
        this.token = newToken;
    }
}
