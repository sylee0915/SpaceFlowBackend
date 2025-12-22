package com.example.spaceflow_back.jwt.service;


import com.jwt.domain.RefreshToken;
import com.jwt.domain.User;
import com.jwt.exception.InvalidTokenException;
import com.jwt.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    /**
     * Refresh Token을 저장하거나, 이미 존재하는 경우 업데이트합니다.
     * @param user Refresh Token을 발급받은 사용자
     * @param token 새로 생성된 Refresh Token 문자열
     * @return 저장되거나 업데이트된 RefreshToken 엔티티
     */
    @Transactional
    public RefreshToken saveOrUpdate(User user, String token) {
        // 기존 Refresh Token이 있는지 확인
        RefreshToken refreshToken = refreshTokenRepository.findByUserId(user.getId())
                .orElse(null);

        if (refreshToken == null) {
            // 없으면 새로 생성하여 저장
            refreshToken = RefreshToken.builder()
                    .token(token)
                    .userId(user.getId())
                    .build();
        } else {
            // 있으면 토큰 값만 업데이트
            refreshToken.updateToken(token);
        }
        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * Refresh Token 문자열로 DB에서 토큰 정보를 조회합니다.
     * @param token Refresh Token 문자열
     * @return RefreshToken 엔티티
     */
    @Transactional(readOnly = true)
    public RefreshToken findByToken(String token) {
        return refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new InvalidTokenException("유효하지 않은 Refresh Token입니다."));
    }

    /**
     * 사용자 ID로 저장된 Refresh Token을 삭제합니다. (로그아웃 시 사용)
     * @param userId 사용자 ID
     */
    @Transactional
    public void deleteByUserId(Long userId) {
        refreshTokenRepository.deleteByUserId(userId);
    }
}
