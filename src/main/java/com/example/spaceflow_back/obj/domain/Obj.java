package com.example.spaceflow_back.obj.domain;

import com.example.spaceflow_back.company.domain.Company;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Table(name = "objects")
public class Obj {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "company_id", nullable = false)
    private Company company; // 어느 회사 소유의 방인지

    @Column(nullable = false)
    private String name; // 방 이름 (예: 회의실 A)

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "category_id")
    private Category category; // 카테고리 (예: 회의실, 휴게실)

    private String start; // 이용 시작 가능 시간
    private String end;   // 이용 종료 시간
}