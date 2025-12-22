package com.example.spaceflow_back.test;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class TestController {

    @GetMapping("/api/test")
    public Map<String, String> testConnection() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "백엔드 서버와 연결에 성공했습니다!");
        response.put("status", "success");
        return response;
    }
}
