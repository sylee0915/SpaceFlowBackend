package com.example.spaceflow_back.jwt.security;

import com.example.spaceflow_back.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * Spring Security의 loadUserByUsername 메서드를 구현
     * 사용자의 이메일을 기반으로 DB에서 사용자 정보를 가져와 UserDetails 객체(CustomUserDetails)로 변환하여 반환
     */
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email)
                .map(user -> CustomUserDetails.builder()
                        .id(user.getId())
                        .username(user.getEmail())
                        .password(user.getPassword())
                        .authority(user.getRole())
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다. Email: " + email));
    }
}
