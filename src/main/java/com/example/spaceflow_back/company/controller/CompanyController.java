package com.example.spaceflow_back.company.controller;

import com.example.spaceflow_back.company.dto.request.CompanyRequest;
import com.example.spaceflow_back.company.service.CompanyService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/companies")
@RequiredArgsConstructor
public class CompanyController {

    private final CompanyService companyService;

    /**
     * 신규 회사 등록 API
     * POST /api/companies
     */
    @PostMapping
    public ResponseEntity<Long> createCompany(@RequestBody CompanyRequest request) {
        // 서비스 호출 후 생성된 회사의 ID를 반환받음
        Long companyId = companyService.createCompany(request);

        // HTTP 200 OK 상태와 함께 생성된 ID를 응답
        return ResponseEntity.ok(companyId);
    }
}