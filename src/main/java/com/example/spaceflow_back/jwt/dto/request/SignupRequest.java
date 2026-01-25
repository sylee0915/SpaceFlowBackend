package com.example.spaceflow_back.jwt.dto.request;

import com.example.spaceflow_back.company.domain.Company;
import com.example.spaceflow_back.jwt.domain.User;
import com.example.spaceflow_back.jwt.domain.UserRole; // Enum 임포트
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
    private Long companyId;
    private String role; // 프론트에서 넘어오는 값은 여전히 String으로 받습니다.

    public User toEntity(PasswordEncoder passwordEncoder, Company company) {
        return User.builder()
                .email(email)
                .password(passwordEncoder.encode(password))
                .nickname(nickname)
                .company(company)
                .role(convertToUserRole(this.role)) // Enum 변환 메서드 호출
                .access("PENDING")
                .build();
    }

    // String role을 안전하게 Enum으로 변환하는 프라이빗 메서드
    private UserRole convertToUserRole(String roleStr) {
        if (roleStr == null || roleStr.isEmpty()) {
            return UserRole.ROLE_USER; // 기본값
        }

        try {
            // "USER" -> UserRole.ROLE_USER / "ROLE_USER" -> UserRole.ROLE_USER 양쪽 다 대응
            String formattedRole = roleStr.startsWith("ROLE_") ? roleStr : "ROLE_" + roleStr;
            return UserRole.valueOf(formattedRole.toUpperCase());
        } catch (IllegalArgumentException e) {
            // 잘못된 값이 들어올 경우 기본값 혹은 예외 처리
            return UserRole.ROLE_USER;
        }
    }
}