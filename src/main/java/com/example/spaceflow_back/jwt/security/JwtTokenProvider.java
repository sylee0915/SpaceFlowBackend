package com.example.spaceflow_back.jwt.security;

import com.example.spaceflow_back.config.JwtProperties;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

@Slf4j
@Component
public class JwtTokenProvider {

    private final Key key;
    private final JwtProperties jwtProperties;

    public JwtTokenProvider(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        // Base64로 인코딩된 Secret Key를 디코딩하여 Key 객체 생성
        byte[] keyBytes = Decoders.BASE64.decode(jwtProperties.getSecretKey());
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Access Token 생성: CustomUserDetails에서 ID를 추출하여 클레임에 포함합니다.
     */
    public String generateAccessToken(Authentication authentication) {
        // 🚨 CustomUserDetails에서 ID를 추출합니다.
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        Long userId = userDetails.getId();

        return generateToken(
                userDetails.getUsername(), // Subject: email
                userDetails.getAuthorities(),
                userId, // userId 클레임으로 전달
                jwtProperties.getAccessTokenExpirationTime()
        );
    }

    /**
     * Refresh Token 생성: Subject와 클레임에 userId를 사용합니다.
     */
    public String generateRefreshToken(Long userId) {
        return generateToken(
                String.valueOf(userId), // Subject: userId (String)
                null, // Refresh Token은 권한 정보 불필요
                userId, // userId 클레임으로 전달
                jwtProperties.getRefreshTokenExpirationTime()
        );
    }

    /**
     * 실제 토큰 생성 로직: userId 매개변수가 추가되었습니다.
     */
    private String generateToken(String subject, Collection<? extends GrantedAuthority> authorities, Long userId, long validityInMilliseconds) {

        long now = (new Date()).getTime();
        Date validity = new Date(now + validityInMilliseconds);

        ClaimsBuilder claimsBuilder = Jwts.claims().setSubject(subject);

        // 🚨 사용자 ID를 JWT 클레임에 추가합니다. (500 에러 해결의 핵심)
        if (userId != null) {
            claimsBuilder.add("userId", userId);
        }

        // Access Token인 경우에만 Authority 클레임 추가
        if (authorities != null) {
            String authorityString = authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .findFirst().orElse("ROLE_USER");
            claimsBuilder.add("auth", authorityString);
        }

        Map<String, Object> claims = claimsBuilder.build();

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date(now))
                .setExpiration(validity)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }


    /**
     * JWT에서 인증 정보(Authentication)를 추출합니다.
     */
    public Authentication getAuthentication(String token) {
        Claims claims = parseClaims(token);

        String principalEmail = claims.getSubject();
        String authority = claims.get("auth", String.class);
        // 🚨 JWT 클레임에서 userId를 추출합니다.
        Long userId = claims.get("userId", Long.class);

        // 🚨 추출된 ID를 CustomUserDetails에 전달하여 null이 되지 않도록 합니다.
        CustomUserDetails userDetails = CustomUserDetails.builder()
                .id(userId)
                .username(principalEmail)
                .authority(authority)
                .build();

        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    /**
     * 토큰 유효성 검사 및 파싱 (jjwt 0.12.x 버전 호환)
     */
    public boolean validateToken(String token) {
        try {
            // Jwts.parser()를 사용하고 verifyWith(key)로 서명 검증을 설정합니다.
            Jwts.parser()
                    .verifyWith((SecretKey) key) // jjwt-impl에 정의된 메서드
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명입니다.", e);
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT입니다.", e);
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT입니다.", e);
        } catch (IllegalArgumentException e) {
            log.info("JWT가 잘못되었습니다.", e);
        }
        return false;
    }

    /**
     * 토큰에서 Claims를 추출합니다. (만료된 토큰에서도 추출)
     */
    public Claims parseClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith((SecretKey) key) // verifyWith(Key) 사용
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            // 만료된 토큰의 경우에도 클레임은 반환
            return e.getClaims();
        }
    }
}