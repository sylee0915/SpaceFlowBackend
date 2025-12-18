package com.jwt.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestControllerAdvice // 전역적으로 예외를 처리하는 어노테이션
public class GlobalExceptionHandler {

    /**
     * RuntimeException (일반적인 런타임 예외) 처리
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, String>> handleRuntimeException(RuntimeException e) {
        log.error("Unhandled Runtime Exception: {}", e.getMessage(), e);
        return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "SERVER_ERROR", "내부 서버 오류가 발생했습니다.");
    }

    /**
     * UserNotFoundException 처리 -> 404 Not Found
     */
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<Map<String, String>> handleUserNotFoundException(UserNotFoundException e) {
        log.warn("User Not Found: {}", e.getMessage());
        return createErrorResponse(HttpStatus.NOT_FOUND, "USER_NOT_FOUND", e.getMessage());
    }

    /**
     * InvalidTokenException 처리 -> 401 Unauthorized
     */
    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<Map<String, String>> handleInvalidTokenException(InvalidTokenException e) {
        log.warn("Invalid Token Exception: {}", e.getMessage());
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "INVALID_TOKEN", e.getMessage());
    }

    /**
     * IllegalArgumentException 처리 (예: 중복 회원가입 시도) -> 400 Bad Request
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleIllegalArgumentException(IllegalArgumentException e) {
        log.warn("Illegal Argument Exception: {}", e.getMessage());
        return createErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_ARGUMENT", e.getMessage());
    }

    /**
     * 에러 응답 DTO를 생성하는 유틸리티 메서드
     */
    private ResponseEntity<Map<String, String>> createErrorResponse(HttpStatus status, String code, String message) {
        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("code", code);
        errorResponse.put("message", message);

        return new ResponseEntity<>(errorResponse, status);
    }
}
