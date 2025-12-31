package com.example.spaceflow_back.jwt.security;

import com.example.spaceflow_back.config.JwtProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final JwtProperties jwtProperties;

    /**
     * 1. Request Header에서 JWT 추출
     * 2. 토큰 유효성 검증
     * 3. 유효하다면 Security Context에 인증 정보 저장
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // 1. Request Header에서 토큰 추출
        String token = resolveToken(request);

        // 2. 토큰 유효성 검사 및 인증
        if (token != null && jwtTokenProvider.validateToken(token)) {
            // 유효한 토큰일 경우 Authentication 객체를 가져와 SecurityContext에 저장
            Authentication authentication = jwtTokenProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Request Header에서 JWT를 추출하여 반환합니다.
     * @param request HTTP 요청
     * @return JWT 문자열 (Bearer 제거) 또는 null
     */
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(jwtProperties.getHeaderString()); // 예: Authorization 헤더 값

        // "Bearer "로 시작하는지 확인하고, Prefix 제거 후 토큰 부분만 추출
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(jwtProperties.getTokenPrefix())) {
            return bearerToken.substring(jwtProperties.getTokenPrefix().length()).trim();
        }
        return null;
    }
}
