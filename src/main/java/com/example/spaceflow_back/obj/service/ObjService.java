package com.example.spaceflow_back.obj.service;

import com.example.spaceflow_back.company.domain.Company;
import com.example.spaceflow_back.company.repository.CompanyRepository;
import com.example.spaceflow_back.jwt.security.CustomUserDetails;
import com.example.spaceflow_back.obj.domain.Category;
import com.example.spaceflow_back.obj.domain.Obj;
import com.example.spaceflow_back.obj.dto.request.ObjRequest;
import com.example.spaceflow_back.obj.repository.CategoryRepository;
import com.example.spaceflow_back.obj.repository.ObjRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ObjService {

        private final ObjRepository objRepository;
        private final CompanyRepository companyRepository;
        private final CategoryRepository categoryRepository;

        @Transactional
        public void createObj(ObjRequest request, CustomUserDetails userDetails) {
            // 1. 현재 로그인한 사용자의 회사 정보를 가져옴
            Company company = companyRepository.findById(userDetails.getCompanyId())
                    .orElseThrow(() -> new IllegalArgumentException("회사를 찾을 수 없습니다."));

            // 2. 카테고리 조회 (있을 경우)
            Category category = categoryRepository.findById(request.getCategoryId())
                    .orElseThrow(() -> new IllegalArgumentException("카테고리를 찾을 수 없습니다."));

            // 3. 해당 회사의 이름으로 방(Obj) 생성
            Obj obj = Obj.builder()
                    .company(company) // 로그인한 유저의 회사와 연결!
                    .name(request.getName())
                    .category(category)
                    .start(request.getStart())
                    .end(request.getEnd())
                    .build();

            objRepository.save(obj);
        }
    }

