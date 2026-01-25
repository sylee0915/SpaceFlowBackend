package com.example.spaceflow_back.company.domain;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum CompanyWay {
    DOMAIN("도메인 방식"),
    ACCESS("액세스 코드 방식");

    private final String description;
}