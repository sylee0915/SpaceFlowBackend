package com.example.spaceflow_back.obj.dto.response;

import com.example.spaceflow_back.obj.domain.Obj;
import lombok.Builder;
import lombok.Getter;


    @Getter
    @Builder
    public class ObjResponse {
        private Long id;         // 생성된 방의 ID
        private String name;     // 방 이름
        private String categoryName; // 카테고리 이름 (예: "회의실")

        public static ObjResponse from(Obj obj) {
            return ObjResponse.builder()
                    .id(obj.getId())
                    .name(obj.getName())
                    .categoryName(obj.getCategory().getName())
                    .build();
        }
    }

