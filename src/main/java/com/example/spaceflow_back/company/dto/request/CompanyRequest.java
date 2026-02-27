package com.example.spaceflow_back.company.dto.request;

import com.example.spaceflow_back.company.domain.CompanyWay;

public class CompanyRequest {
    private String name;
    private CompanyWay way;
    private String domainAddress;

    // 기본 생성자
    public CompanyRequest() {}

    // Getter 메서드들 (이게 있어야 서비스에서 에러가 안 남)
    public String getName() { return name; }
    public CompanyWay getWay() { return way; }
    public String getDomainAddress() { return domainAddress; }
}