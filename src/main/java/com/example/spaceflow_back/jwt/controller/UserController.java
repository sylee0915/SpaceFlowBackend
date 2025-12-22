package com.example.spaceflow_back.jwt.controller;

import com.jwt.domain.User;
import com.jwt.repository.UserRepository;
import com.jwt.security.CustomUserDetails;
import com.jwt.exception.UserNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;

    /**
     * 현재 로그인된 사용자 정보를 조회하는 보호된 엔드포인트 예시
     * @AuthenticationPrincipal을 통해 JWT에서 추출된 CustomUserDetails 객체를 받습니다.
     */
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(@AuthenticationPrincipal CustomUserDetails userDetails) {
        // userDetails.getId()는 이제 JWT 클레임에서 추출된 실제 사용자 ID를 반환합니다.
        Long userId = userDetails.getId();

        if (userId == null) {
            // 토큰에 사용자 ID가 없는 경우 (JWT 파싱 로직 오류 시)
            throw new UserNotFoundException("JWT does not contain valid user ID.");
        }

        // JWT에서 추출된 ID를 사용하여 DB에서 최신 사용자 정보 조회
        User user = userRepository.findById(userId)
                .orElseThrow(UserNotFoundException::new);

        Map<String, Object> response = new HashMap<>();
        response.put("id", user.getId());
        response.put("email", user.getEmail());
        response.put("nickname", user.getNickname());
        response.put("role", user.getRole());

        return ResponseEntity.ok(response);
    }

    /**
     * 인증은 되었지만, 권한 체크가 필요한 엔드포인트 예시
     * (SecurityConfig에서 ROLE_ADMIN 권한을 가진 사용자만 접근 가능하도록 설정할 수 있음)
     */
    @GetMapping("/admin-check")
    public ResponseEntity<String> adminCheck() {
        return ResponseEntity.ok("관리자 권한이 확인되었습니다.");
    }
}