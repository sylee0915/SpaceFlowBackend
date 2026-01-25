package com.example.spaceflow_back.jwt.domain;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum UserRole {
    ROLE_ADMIN("관리자"),
    ROLE_BUSINESS("비즈니스"),
    ROLE_USER("일반 사용자");

    private final String description;
}