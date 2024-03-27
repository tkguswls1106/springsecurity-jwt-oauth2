package com.shj.springboot3.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.shj.springboot3.jwt.JwtExceptionFilter;
import com.shj.springboot3.jwt.JwtFilter;
import com.shj.springboot3.jwt.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// JwtSecurityConfig와 같은 보안 구성 클래스는 WebSecurityConfig 클래스 내에서 .apply() 메서드를 통해 명시적으로 적용하기때문에, JwtSecurityConfig에 @Configuration 어노테이션을 붙이지않아도된다.
@RequiredArgsConstructor
public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {  // 스프링 시큐리티의 커스텀 필터 설정 클래스
    // 필터 체인이란, HTTP 요청이 애플리케이션에 도착할 때 Spring Security에 의해 순차적으로 실행되는 일련의 필터를 의미한다.
    // JwtSecurityConfig 클래스가 상속받는 것들 때문에, Spring Security 설정을 커스터마이즈할 수 있는데 그중 필터 체인을 커스터마이즈할 수 있다.
    // 그리고 configure 메소드를 오버라이드하여 재정의함으로써, 커스텀필터인 JwtFilter를 생성하고 이를 Spring Security의 필터 체인에 등록한다.
    // 그리고 메소드 내에서 addFilterBefore()를 통해 커스텀필터를 UsernamePasswordAuthenticationFilter필터보다 순서를 먼저 실행시키도록 설정하여, JWT의 유효성 검사를 먼저 진행하도록 한다.

    private final TokenProvider tokenProvider;
    private final ObjectMapper objectMapper;


    @Override
    public void configure(HttpSecurity http) {
        JwtFilter customFilter = new JwtFilter(tokenProvider);
        http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);

        JwtExceptionFilter jwtExceptionFilter = new JwtExceptionFilter(objectMapper);
        http.addFilterBefore(jwtExceptionFilter, JwtFilter.class);
    }
}