package com.example.spaceflow_back.obj.controller;

import com.example.spaceflow_back.jwt.security.CustomUserDetails;
import com.example.spaceflow_back.obj.dto.request.ObjRequest;
import com.example.spaceflow_back.obj.service.ObjService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/objs")
@RequiredArgsConstructor
public class ObjController {

    private final ObjService objService;

    @PostMapping
    public ResponseEntity<String> createObj(
            @RequestBody ObjRequest request,
            @AuthenticationPrincipal CustomUserDetails userDetails // 세션/토큰에서 유저 정보 주입
    ) {
        objService.createObj(request, userDetails);
        return ResponseEntity.ok("성공적으로 생성되었습니다.");
    }
}