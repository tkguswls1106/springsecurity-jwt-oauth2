package com.shj.springboot3.oauth.handler;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.shj.springboot3.response.ResponseCode;
import com.shj.springboot3.response.ResponseData;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
public class OAuth2LoginFailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        log.info("OAuth2 소셜 로그인에 실패했습니다. 에러 메시지 : {}", exception.getMessage());

        ObjectMapper objectMapper = new ObjectMapper();
        // 전체 ResponseEntity 객체를 JSON 문자열로 변환.
        ResponseEntity responseEntity = ResponseData.toResponseEntity(ResponseCode.LOGIN_FAIL);
        String jsonString = objectMapper.writeValueAsString(responseEntity);
        // 위의 JSON 문자열에서 "body" 필드만 추출.
        JsonNode rootNode = objectMapper.readTree(jsonString);
        JsonNode dataNode = rootNode.path("body");
        String jsonData = objectMapper.writeValueAsString(dataNode);

        response.getWriter().write(jsonData);
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