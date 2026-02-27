package com.example.spaceflow_back.company.service;

import com.example.spaceflow_back.company.domain.Company;
import com.example.spaceflow_back.company.dto.request.CompanyRequest;
import com.example.spaceflow_back.company.repository.CompanyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class CompanyService {

    private final CompanyRepository companyRepository;

    @Transactional
    public Long createCompany(CompanyRequest request) {
        // 1. 이미 존재하는 회사 이름인지 체크 (선택 사항)
        if (companyRepository.existsByName(request.getName())) {
            throw new IllegalArgumentException("이미 존재하는 회사 이름입니다.");
        }

        // 2. DTO -> Entity 변환 및 저장
        Company company = Company.builder()
                .name(request.getName())
                .way(request.getWay())
                .domainAddress(request.getDomainAddress())
                .build();

        return companyRepository.save(company).getId();
    }
}