package com.shj.springboot3.oauth.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Slf4j
@Component
public class OAuth2LoginFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        log.info("OAuth2 소셜 로그인에 실패했습니다. 에러 메시지 : {}", exception.getMessage());

        String redirectUrl = UriComponentsBuilder.fromUriString("http://localhost:3000/login")
                .build().toUriString();  // 로그인 방식 선택 페이지로 리다이렉트 시킬것.

        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }
}


//@Slf4j
//@Component
//public class OAuth2LoginFailureHandler implements AuthenticationFailureHandler {
//
//    @Override
//    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
//        response.getWriter().write("소셜 로그인 실패! 서버 로그를 확인해주세요.");
//        log.info("소셜 로그인에 실패했습니다. 에러 메시지 : {}", exception.getMessage());
//    }
//}