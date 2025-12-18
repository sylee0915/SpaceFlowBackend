package com.jwt.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * application.yml 파일의 'jwt' 설정값을 매핑하는 클래스
 */
@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "jwt") // application.yml의 jwt: 아래 설정을 읽어옴
public class JwtProperties {

    private String secretKey;
    private long accessTokenExpirationTime;
    private long refreshTokenExpirationTime;
    private String tokenPrefix;
    private String headerString;
}