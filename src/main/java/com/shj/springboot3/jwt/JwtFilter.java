package com.shj.springboot3.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {  // 커스텀 필터 클래스
    // JwtFilter 클래스의 주된 역할은 HTTP 요청을 중간에서 가로채어 JWT를 처리하고, 해당 토큰을 사용하여 사용자를 인증하는 것이다.
    // 자세히는, 이 클래스는 JWT 토큰을 추출하고 유효성을 검사한 후, 유효한 경우에는 해당 토큰을 사용하여 사용자를 인증하고, Spring Security의 SecurityContextHolder에 해당 인증 정보를 설정하는 역할을 함.

    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";
    private final TokenProvider tokenProvider;  // @RequiredArgsConstructor로 의존DI주입으로, JwtFilter(TokenProvider tokenProvider){} 생성자를 자동 생성해줌.


    private String resolveToken(HttpServletRequest request) {  // HttpServletRequest는 HTTP 요청 정보를 캡슐화하는 객체이다. 이 객체는 클라이언트에서 서버로 전송된 요청 메시지의 내용과 속성을 확인하고 수정할 수 있다.
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {  // 추출된 헤더값이 null이 아닌가 && "Bearer "로 시작하는가 ("Bearer " 다음에 실제 토큰이 오는 것이 관례임.)
            return bearerToken.substring(7);  // 토큰이 유효하다면, 앞부분인 "Bearer "을 제외하여 7인덱스부터 끝까지인 실제 토큰 문자열을 반환함.
        }
        return null;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String jwt = resolveToken(request);  // 토큰값 문자열 리턴

        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {  // 토큰값이 null이 아닌가 && 토큰의 서명이 일치하고 유효한가 (JWT 유효성 검사)
            Authentication authentication = tokenProvider.getAuthentication(jwt);  // JWT 토큰을 사용하여 사용자를 인증함.
            SecurityContextHolder.getContext().setAuthentication(authentication);  // 그 다음으로, Spring Security의 SecurityContextHolder에 인증 정보를 설정함.
        }

        filterChain.doFilter(request, response);  // 현재 필터의 작업이 끝난 후, 다음 필터로 HTTP 요청을 전달함.
    }
}