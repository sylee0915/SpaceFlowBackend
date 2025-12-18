package com.jwt.repository;


import com.jwt.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * 이메일을 통해 User를 조회합니다. Spring Security에서 사용됩니다.
     */
    Optional<User> findByEmail(String email);

    /**
     * 이미 존재하는 이메일인지 확인합니다. 회원가입 시 중복 검사에 사용됩니다.
     */
    boolean existsByEmail(String email);
}
