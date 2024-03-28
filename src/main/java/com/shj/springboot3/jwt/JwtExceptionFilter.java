package com.shj.springboot3.jwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.shj.springboot3.response.ResponseCode;
import com.shj.springboot3.response.ResponseData;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtExceptionFilter extends OncePerRequestFilter {

    private final ObjectMapper objectMapper;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);
        } catch (JwtException e) {
            response.setStatus(401);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("UTF-8");

            // 전체 ResponseEntity 객체를 JSON 문자열로 변환.
            ResponseEntity responseEntity = ResponseData.toResponseEntity(ResponseCode.UNAUTHORIZED_ERROR);
            String jsonString = objectMapper.writeValueAsString(responseEntity);
            // 위의 JSON 문자열에서 "body" 필드만 추출.
            JsonNode rootNode = objectMapper.readTree(jsonString);
            JsonNode dataNode = rootNode.path("body");
            String jsonData = objectMapper.writeValueAsString(dataNode);

            response.getWriter().write(jsonData);
        }
    }
}


//@Component
//@RequiredArgsConstructor
//public class JwtExceptionFilter extends OncePerRequestFilter {
//
//    private final ObjectMapper objectMapper;
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//        try {
//            filterChain.doFilter(request, response);
//        } catch (JwtException e) {
//            response.setStatus(401);
//            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//            response.setCharacterEncoding("UTF-8");
//            objectMapper.writeValue(response.getWriter(), StatusResponseDto.addStatus(401));
//        }
//    }
//}

//@Getter
//@AllArgsConstructor
//@JsonInclude(JsonInclude.Include.NON_NULL)  // dto를 JSON으로 변환 시 null값인 field 제외
//public class StatusResponseDto {
//    private Integer status;
//    private Object data;
//
//    public StatusResponseDto(Integer status) {
//        this.status = status;
//    }
//
//    public static StatusResponseDto addStatus(Integer status) {
//        return new StatusResponseDto(status);
//    }
//
//    public static StatusResponseDto success(){
//        return new StatusResponseDto(200);
//    }
//    public static StatusResponseDto success(Object data){
//        return new StatusResponseDto(200, data);
//    }
//}