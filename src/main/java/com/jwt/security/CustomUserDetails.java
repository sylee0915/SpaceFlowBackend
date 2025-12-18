package com.jwt.security;

import lombok.Builder;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Getter
public class CustomUserDetails implements UserDetails {

    private final String username; // 여기서는 User의 email
    private final String password; // 실제 암호화된 비밀번호 (인증 시 사용)
    private final Long id; // 사용자 고유 ID (JWT 페이로드에서 추출될 값)
    private final Collection<? extends GrantedAuthority> authorities;

    /**
     * UserDetailsService가 DB에서 조회한 User 정보로 CustomUserDetails를 생성할 때 사용
     * 또는 JwtTokenProvider가 토큰에서 ID, Username, 권한만 추출하여 인증 객체를 만들 때 사용
     */
    @Builder
    public CustomUserDetails(Long id, String username, String password, String authority) {
        this.id = id;
        this.username = username;
        this.password = password != null ? password : ""; // Null 방지
        this.authorities = List.of(new SimpleGrantedAuthority(authority != null ? authority : "ROLE_USER"));
    }

    // --- UserDetails 필수 메서드 구현 ---

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username; // 이메일 반환
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}