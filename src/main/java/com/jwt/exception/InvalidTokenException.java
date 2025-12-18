package com.jwt.exception;

/**
 * JWT 또는 Refresh Token이 유효하지 않을 때 발생하는 커스텀 예외
 */
public class InvalidTokenException extends RuntimeException {

    public InvalidTokenException() {
        super("유효하지 않은 토큰 정보입니다.");
    }

    public InvalidTokenException(String message) {
        super(message);
    }
}
