package com.example.spaceflow_back.obj.repository;

import com.example.spaceflow_back.obj.domain.Obj;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ObjRepository extends JpaRepository<Obj, Long> {
}
