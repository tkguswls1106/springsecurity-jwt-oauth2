package com.shj.springboot3.jwt;

import io.jsonwebtoken.JwtException;
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
import java.util.Arrays;

@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {  // 커스텀 필터 클래스
    // JwtFilter 클래스의 주된 역할은 HTTP 요청을 중간에서 가로채어 JWT를 처리하고, 해당 토큰을 사용하여 사용자를 인증하는 것이다.
    // 자세히는, 이 클래스는 JWT 토큰을 추출하고 유효성을 검사한 후, 유효한 경우에는 해당 토큰을 사용하여 사용자를 인증하고, Spring Security의 SecurityContextHolder에 해당 인증 정보를 설정하는 역할을 함.

    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";
    private final TokenProvider tokenProvider;  // @RequiredArgsConstructor로 의존DI주입으로, JwtFilter(TokenProvider tokenProvider){} 생성자를 자동 생성해줌.


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String jwt = resolveToken(request);  // 토큰값 문자열 리턴

        if(StringUtils.hasText(jwt) && tokenProvider.isExpiredToken(jwt) == true) {  // 토큰값이 null이 아닌가 && 해당 Access Token이 만료되었다면
            // request 접근 순서가, 앞에서부터 차례로 'request 요청 -> filter -> DispatcherServlet -> Spring Context' 이다.
            // 예외를 처리해주는 HandlerInterceptor(= @RestControllerAdvice 달아둔 ExceptionHandler)는 Spring Context 안에 존재하기 때문에,
            // filter에서 던지는 예외는 ExceptionHandler에서 처리할 수 없다.
            // ----------
            // 이를 방지하여 JwtFilter에서 던지는 예외처리를 받아내려면, request 접근 순서의 filter들을 'request 요청 -> JwtExceptionFilter -> JwtFilter'로 두면 된다.
            // 그 이유는 보다 먼저 앞단에 위치한 JwtExceptionFilter가 filterChain.doFilter()로 다음 필터인 JwtFilter를 호출하도록 되어있는데,
            // 필터는 본인에게 발생한 예외처리를, 본인을 호출한 앞단 필터에게 던지도록 되어있기 때문이다.
            // 그래서 JwtFilter에서 발생한 예외는 앞단의 JwtExceptionFilter에게 던져지게 되는것이다.
            throw new JwtException("토큰 만료 - ExpiredJwtException");  // 이 예외처리는 보다 앞단의 필터인 JwtExceptionFilter에게 던져짐.
        }

        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {  // 토큰값이 null이 아닌가 && 토큰의 서명이 일치하고 유효한가 (JWT 유효성 검사)
            Authentication authentication = tokenProvider.getAuthentication(jwt);  // JWT 토큰을 사용하여 사용자를 인증함.
            SecurityContextHolder.getContext().setAuthentication(authentication);  // 그 다음으로, Spring Security의 SecurityContextHolder에 인증 정보를 설정함.
        }

        filterChain.doFilter(request, response);  // 현재 필터의 작업이 끝난 후, 다음 필터로 HTTP 요청을 전달함.
    }

    private String resolveToken(HttpServletRequest request) {  // HttpServletRequest는 HTTP 요청 정보를 캡슐화하는 객체이다. 이 객체는 클라이언트에서 서버로 전송된 요청 메시지의 내용과 속성을 확인하고 수정할 수 있다.
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {  // 추출된 헤더값이 null이 아닌가 && "Bearer "로 시작하는가 ("Bearer " 다음에 실제 토큰이 오는 것이 관례임.)
            return bearerToken.substring(7);  // 토큰이 유효하다면, 앞부분인 "Bearer "을 제외하여 7인덱스부터 끝까지인 실제 토큰 문자열을 반환함.
        }
        return null;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        // 이 메소드는 프론트엔드 팀원이 무슨 경우든간에 일단 헤더에 토큰을 넣고 api요청보내는 사람일때, permitAll()을 해두고 로그인 필요없는 기능 api를 호출할때 헤더의 토큰 만료검사를 피하기 위해 작성된 메소드이다.
        // 그렇기에, 정석적으로 프론트엔드에서 jwt헤더를 알맞게 잘관리해서 넣고 빼가며 적절히 api요청을 잘보내준다면, 사실상 shouldNotFilter()는 사용할 경우가 없을것이다.
        String[] excludePath = {"/reissue"};
        String path = request.getRequestURI();
        return Arrays.stream(excludePath).anyMatch(path::startsWith);
    }
}