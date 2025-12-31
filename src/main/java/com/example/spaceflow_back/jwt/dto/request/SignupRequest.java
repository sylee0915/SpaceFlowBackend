package com.example.spaceflow_back.jwt.dto.request;


import com.example.spaceflow_back.jwt.domain.User;
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
    private Long companyId; // 프론트에서 넘어올 필드 추가
    private String role;    // ADMIN, BUSINESS, USER 중 하나

    // DTO를 엔티티로 변환하는 메서드
    public User toEntity(PasswordEncoder passwordEncoder) {
        return User.builder()
                .email(email)
                .password(passwordEncoder.encode(password))
                .nickname(nickname)
                .companyId(companyId)   // 엔티티에 세팅
                .role(role != null ? role : "ROLE_USER") // 기본값 처리
                .access("PENDING")      // 가입 시 기본 상태는 대기중
                .build();
    }
}
