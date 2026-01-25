package com.example.spaceflow_back.obj.dto.request;

import com.example.spaceflow_back.company.domain.Company;
import com.example.spaceflow_back.obj.domain.Category;
import com.example.spaceflow_back.obj.domain.Obj;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class ObjRequest {

    private String name;        // 방 이름
    private Long categoryId;    // 선택한 카테고리 번호
    private String start;       // 시작 시간 (예: "09:00")
    private String end;         // 종료 시간 (예: "18:00")

    // DTO를 엔티티로 변환하는 메서드
    public Obj toEntity(Company company, Category category) {
        return Obj.builder()
                .name(this.name)
                .company(company)   // 서비스에서 조회한 회사 객체
                .category(category) // 서비스에서 조회한 카테고리 객체
                .start(this.start)
                .end(this.end)
                .build();
    }
}