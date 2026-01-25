package com.example.spaceflow_back.obj.repository;

import com.example.spaceflow_back.obj.domain.Category;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CategoryRepository extends JpaRepository<Category, Long> {
}
