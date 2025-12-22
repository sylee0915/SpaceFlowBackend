package com.example.spaceflow_back.jwt.dto.request;


import com.jwt.domain.User;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.crypto.password.PasswordEncoder;

@Getter
@Setter
@NoArgsConstructor
public class SignupRequest {

    private String email;
    private String password;
    private String nickname;

    // DTO를 엔티티로 변환하는 메서드
    public User toEntity(PasswordEncoder passwordEncoder) {
        return User.builder()
                .email(this.email)
                .password(passwordEncoder.encode(this.password)) // 반드시 암호화
                .nickname(this.nickname)
                .role("ROLE_USER") // 기본 권한 부여
                .build();
    }
}
