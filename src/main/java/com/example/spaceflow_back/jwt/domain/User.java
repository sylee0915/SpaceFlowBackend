package com.example.spaceflow_back.jwt.domain;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

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
    @Column(name = "company_id")
    private Long companyId;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String nickname;

    // ROLE_ADMIN, ROLE_BUSINESS, ROLE_USER 등으로 저장
    @Column(nullable = false)
    private String role;

    // PENDING, COMPLETED 등 상태값
    @Column(nullable = false)
    private String access;

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(this.role));
    }
}
