package com.example.spaceflow_back.jwt.controller;

import com.jwt.dto.request.LoginRequest;
import com.jwt.dto.request.SignupRequest;
// TokenRefreshRequest DTO는 이제 사용되지 않으므로 import를 제거합니다.
// import com.jwt.dto.request.TokenRefreshRequest;
import com.jwt.dto.response.LoginResponse;
import com.jwt.dto.response.TokenRefreshResponse;
import com.jwt.security.CustomUserDetails;
import com.jwt.service.AuthService;
import jakarta.servlet.http.HttpServletResponse; // HTTP 응답 처리를 위해 추가
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie; // 쿠키 객체 생성을 위해 추가
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private static final String REFRESH_TOKEN_COOKIE_NAME = "refreshToken";

    /**
     * 회원가입 엔드포인트
     */
    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody SignupRequest request) {
        authService.signup(request);
        return ResponseEntity.status(HttpStatus.CREATED).body("회원가입이 성공적으로 완료되었습니다.");
    }

    /**
     * 로그인 엔드포인트 (Access Token 발급 및 Refresh Token은 HttpOnly 쿠키로 설정)
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request,
                                               HttpServletResponse response) { // HttpServletResponse 주입

        LoginResponse loginResponse = authService.login(request);

        // 1. Refresh Token 추출 및 HttpOnly 쿠키 생성
        String refreshToken = loginResponse.getRefreshToken();
        // AuthService에서 만료 시간(초 단위)을 가져옵니다.
        long maxAge = authService.getRefreshTokenMaxAgeInSeconds();

        ResponseCookie cookie = ResponseCookie.from(REFRESH_TOKEN_COOKIE_NAME, refreshToken)
                .httpOnly(true)       // HttpOnly: JS 접근 방지 (XSS 공격 방어)
                .secure(true)         // Secure: HTTPS에서만 전송 (운영 환경 필수)
                .sameSite("Strict")   // SameSite: CSRF 방어
                .path("/auth")        // 쿠키가 적용될 경로 (일반적으로 /auth 또는 /)
                .maxAge(maxAge)       // Refresh Token 만료 시간
                .build();

        // 2. 응답 헤더에 쿠키 추가
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        // 3. 보안: 응답 본문에서 Refresh Token 제거 후 반환 (오직 Access Token만 노출)
        loginResponse.setRefreshToken(null);

        return ResponseEntity.ok(loginResponse);
    }

    /**
     * 토큰 갱신 엔드포인트 (Refresh Token 쿠키로 새 Access Token 발급)
     * @CookieValue를 사용하여 쿠키에서 Refresh Token 문자열을 직접 받습니다.
     */
    @PostMapping("/refresh")
    public ResponseEntity<TokenRefreshResponse> refresh(@CookieValue(name = REFRESH_TOKEN_COOKIE_NAME, required = false) String refreshToken) {

        if (refreshToken == null) {
            // 쿠키에 리프레시 토큰이 없는 경우 (로그아웃되었거나 토큰이 없는 상태)
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // AuthService의 refresh 메서드는 이제 문자열을 인수로 받습니다.
        TokenRefreshResponse response = authService.refresh(refreshToken);
        return ResponseEntity.ok(response);
    }

    /**
     * 로그아웃 엔드포인트 (DB에서 Refresh Token 무효화 및 쿠키 삭제)
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal CustomUserDetails userDetails,
                                       HttpServletResponse response) {

        // 1. DB에서 Refresh Token 정보 삭제
        authService.logout(userDetails.getId());

        // 2. HttpOnly 쿠키 삭제 (만료 시간을 0으로 설정)
        ResponseCookie cookie = ResponseCookie.from(REFRESH_TOKEN_COOKIE_NAME, "")
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/auth")
                .maxAge(0) // 즉시 만료
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return ResponseEntity.ok().build();
    }
}