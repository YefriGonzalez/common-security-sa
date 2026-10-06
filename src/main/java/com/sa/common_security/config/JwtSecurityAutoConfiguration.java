package com.sa.common_security.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class JwtSecurityAutoConfiguration {

    @Bean
    public JwtClaimsFilter jwtClaimsFilter(
            @Value("${security.jwt.secret-key}") String secretKey) {

        return new JwtClaimsFilter(secretKey);
    }
}