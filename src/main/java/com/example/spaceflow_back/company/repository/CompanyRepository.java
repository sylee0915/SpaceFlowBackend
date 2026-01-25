package com.example.spaceflow_back.company.repository;

import com.example.spaceflow_back.company.domain.Company;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CompanyRepository extends JpaRepository<Company, Long> {
}
