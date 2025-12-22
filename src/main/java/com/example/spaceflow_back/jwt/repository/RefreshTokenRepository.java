package com.example.spaceflow_back.jwt.repository;

import com.jwt.domain.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    /**
     * 토큰 문자열을 통해 RefreshToken을 조회합니다.
     */
    Optional<RefreshToken> findByToken(String token);

    /**
     * 사용자 ID를 통해 RefreshToken을 조회합니다. (사용자당 하나의 RefreshToken을 가정)
     */
    Optional<RefreshToken> findByUserId(Long userId);

    /**
     * 사용자 ID를 통해 RefreshToken을 삭제합니다. (로그아웃 시 사용)
     */
    void deleteByUserId(Long userId);
}
