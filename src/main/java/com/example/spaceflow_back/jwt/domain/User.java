package com.example.spaceflow_back.jwt.domain;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import com.example.spaceflow_back.company.domain.Company;

import java.util.Collection;
import java.util.List;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    // Company 엔티티가 있다면 ManyToOne 등으로 연관관계를 맺는 것이 좋습니다.
    // 만약 단순 ID 저장 방식이라면 아래와 같이 작성합니다.
    // Long companyId 대신 외래키 설정
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "company_id") // 실제 DB 테이블의 FK 컬럼명
    private Company company;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String nickname;

    // String 대신 Enum 사용
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserRole role;

    // PENDING, COMPLETED 등 상태값
    @Column(nullable = false)
    private String access;

    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Enum의 이름(예: "ROLE_ADMIN")을 문자열로 꺼내서 전달해야 합니다.
        return List.of(new SimpleGrantedAuthority(this.role.name()));
    }
}
