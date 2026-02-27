package com.example.spaceflow_back.company.dto.response;

import com.example.spaceflow_back.company.domain.Company;
import com.example.spaceflow_back.company.domain.CompanyWay;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class CompanyResponse {
    private Long id;
    private String name;
    private CompanyWay way;
    private String domainAddress;

    // 엔티티를 DTO로 변환해주는 정적 메서드
    public static CompanyResponse from(Company company) {
        return CompanyResponse.builder()
                .id(company.getId())
                .name(company.getName())
                .way(company.getWay())
                .domainAddress(company.getDomainAddress())
                .build();
    }
}