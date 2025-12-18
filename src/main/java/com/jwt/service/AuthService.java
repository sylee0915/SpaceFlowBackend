package com.jwt.service;

import com.jwt.config.JwtProperties;
import com.jwt.domain.RefreshToken;
import com.jwt.domain.User;
import com.jwt.dto.request.LoginRequest;
import com.jwt.dto.request.SignupRequest;
import com.jwt.dto.response.LoginResponse;
import com.jwt.dto.response.TokenRefreshResponse;
import com.jwt.exception.InvalidTokenException;
import com.jwt.exception.UserNotFoundException;
import com.jwt.repository.UserRepository;
import com.jwt.security.CustomUserDetails;
import com.jwt.security.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
// TokenRefreshRequest DTO는 이제 사용되지 않으므로 import를 제거해야 합니다.
// 하지만 다른 클래스들이 이 파일을 아직 참조할 수 있으므로, 현재 코드에서는 주석 처리만 합니다.
// import com.jwt.dto.request.TokenRefreshRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final JwtProperties jwtProperties;

    /**
     * 회원가입 로직
     * @param request 회원가입 요청 DTO
     * @return 가입된 User 엔티티
     */
    @Transactional
    public User signup(SignupRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("이미 존재하는 이메일입니다: " + request.getEmail());
        }

        User user = request.toEntity(passwordEncoder);
        return userRepository.save(user);
    }

    /**
     * 로그인 및 Access/Refresh Token 발급 로직
     * @param request 로그인 요청 DTO
     * @return LoginResponse (토큰 정보 포함)
     */
    @Transactional
    public LoginResponse login(LoginRequest request) {
        // 1. UsernamePasswordAuthenticationToken 생성
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword());

        // 2. 실제 인증 수행 (CustomUserDetailsService의 loadUserByUsername 호출)
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // 3. 인증 성공 후, Access Token 및 Refresh Token 생성
        String accessToken = jwtTokenProvider.generateAccessToken(authentication);

        // 인증 객체에서 사용자 ID를 추출
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        Long userId = userDetails.getId();

        String refreshToken = jwtTokenProvider.generateRefreshToken(userId);

        // 4. Refresh Token을 DB에 저장 (또는 업데이트)
        User user = userRepository.findById(userId).orElseThrow(UserNotFoundException::new);
        refreshTokenService.saveOrUpdate(user, refreshToken);

        // 5. 응답 DTO 생성
        return LoginResponse.builder()
                .tokenType(jwtProperties.getTokenPrefix().trim())
                .accessToken(accessToken)
                .refreshToken(refreshToken) // Controller에서 이 값을 추출하여 쿠키로 설정한 뒤, null 처리할 예정입니다.
                .accessTokenExpiresIn(jwtProperties.getAccessTokenExpirationTime())
                .build();
    }

    /**
     * Refresh Token을 이용한 Access Token 갱신 로직
     * @param refreshToken 쿠키에서 추출한 Refresh Token 문자열 (DTO 대신 직접 받음)
     * @return TokenRefreshResponse (새 Access Token 포함)
     */
    @Transactional
    // 메서드 시그니처 변경: TokenRefreshRequest request -> String refreshToken
    public TokenRefreshResponse refresh(String refreshToken) {

        // 1. Refresh Token 유효성 검증
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            throw new InvalidTokenException("유효하지 않거나 만료된 Refresh Token입니다.");
        }

        // 2. DB에 저장된 토큰인지 확인 및 사용자 ID 추출
        RefreshToken storedToken = refreshTokenService.findByToken(refreshToken);
        Claims claims = jwtTokenProvider.parseClaims(refreshToken);
        Long userId = Long.valueOf(claims.getSubject());

        if (!storedToken.getUserId().equals(userId)) {
            // 토큰에 포함된 사용자 ID와 DB에 저장된 사용자 ID가 일치하는지 확인 (보안 강화)
            throw new InvalidTokenException("토큰 소유자가 일치하지 않습니다.");
        }

        // 3. 새로운 Access Token 생성
        User user = userRepository.findById(userId)
                .orElseThrow(UserNotFoundException::new);

        // 새 Access Token 생성을 위해 UserDetails 기반 Authentication 객체를 수동으로 생성
        Authentication newAuthentication = new UsernamePasswordAuthenticationToken(
                new CustomUserDetails(user.getId(), user.getEmail(), user.getPassword(), user.getRole()),
                null,
                user.getAuthorities()
        );

        String newAccessToken = jwtTokenProvider.generateAccessToken(newAuthentication);

        // 4. 응답 DTO 생성
        return TokenRefreshResponse.builder()
                .tokenType(jwtProperties.getTokenPrefix().trim())
                .accessToken(newAccessToken)
                .accessTokenExpiresIn(jwtProperties.getAccessTokenExpirationTime())
                .build();
    }

    /**
     * 로그아웃 (DB에서 Refresh Token 삭제)
     * @param userId 로그아웃할 사용자 ID
     */
    @Transactional
    public void logout(Long userId) {
        refreshTokenService.deleteByUserId(userId);
    }

    /**
     * Refresh Token 만료 시간 (초 단위)를 반환합니다. (쿠키 MaxAge 설정용)
     */
    public long getRefreshTokenMaxAgeInSeconds() {
        // JwtProperties의 만료 시간이 밀리초(ms) 단위라고 가정하고 초 단위로 변환합니다.
        return jwtProperties.getRefreshTokenExpirationTime() / 1000;
    }
}