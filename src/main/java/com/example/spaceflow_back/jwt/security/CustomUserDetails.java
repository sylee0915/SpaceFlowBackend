package com.example.spaceflow_back.jwt.security;

import lombok.Builder;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Getter
public class CustomUserDetails implements UserDetails {

    private final Long id;
    private final String username; // email
    private final String password;
    private final Long companyId;   // 추가
    private final String access;    // 추가 (PENDING, COMPLETED)
    private final Collection<? extends GrantedAuthority> authorities;

    /**
     * UserDetailsService가 DB에서 조회한 User 정보로 CustomUserDetails를 생성할 때 사용
     * 또는 JwtTokenProvider가 토큰에서 ID, Username, 권한만 추출하여 인증 객체를 만들 때 사용
     */
    @Builder
    public CustomUserDetails(Long id, String username, String password,
                             Long companyId, String access, String authority) {
        this.id = id;
        this.username = username;
        this.password = password != null ? password : "";
        this.companyId = companyId;
        this.access = access;
        this.authorities = List.of(new SimpleGrantedAuthority(authority != null ? authority : "ROLE_USER"));
    }

    // 계정 활성화 여부를 access 상태와 연동할 수 있습니다.
    @Override
    public boolean isEnabled() {
        // 예: 승인(COMPLETED)된 사용자만 로그인 가능하게 하려면?
        // return "COMPLETED".equals(this.access);
        return true;
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


}