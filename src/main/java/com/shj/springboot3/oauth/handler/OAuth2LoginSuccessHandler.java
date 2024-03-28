package com.shj.springboot3.oauth.handler;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.shj.springboot3.dto.auth.TokenDto;
import com.shj.springboot3.jwt.TokenProvider;
import com.shj.springboot3.oauth.CustomOAuth2User;
import com.shj.springboot3.domain.user.Role;
import com.shj.springboot3.dto.auth.OAuthLoginResponseDto;
import com.shj.springboot3.response.ResponseCode;
import com.shj.springboot3.response.ResponseData;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final TokenProvider tokenProvider;


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("OAuth2 Login 성공!");

        try {
            CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();

            Long userId = oAuth2User.getUserId();
            Role role = oAuth2User.getRole();

            TokenDto tokenDto = tokenProvider.generateTokenDto(userId, role);  // Access & Refresh 토큰 발행.
            String accessToken = tokenDto.getAccessToken();
            log.info("발급된 Access Token : {}", accessToken);
            String refreshToken = tokenDto.getRefreshToken();
            log.info("발급된 Refresh Token : {}", refreshToken);

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json;charset=UTF-8");

            OAuthLoginResponseDto oAuthLoginResponseDto = new OAuthLoginResponseDto();
            oAuthLoginResponseDto.setTokenDto(tokenDto);

            if(oAuth2User.getRole().equals(Role.GUEST)) {  // User의 Role이 GUEST일 경우, 처음 요청한 회원이므로, 회원가입 페이지로 리다이렉트 시켜야함을 프론트에 전달.
                oAuthLoginResponseDto.setIsNewUser(true);
                oAuthLoginResponseDto.setRedirectMessage("신규 회원 입니다. JWT 헤더를 가진채로, 추가정보 입력을 위한 회원가입 페이지로 리다이렉트 시켜주세요.");
            }
            else {  // 이미 한 번 이상 OAuth2 로그인했던 유저일 때 (즉, 이미 회원가입 추가정보를 입력해두었던 유저일때)
                oAuthLoginResponseDto.setIsNewUser(false);
                oAuthLoginResponseDto.setRedirectMessage("기존 회원 입니다. JWT 헤더를 가진채로, 메인 페이지로 리다이렉트 시켜주세요.");
            }

            ObjectMapper objectMapper = new ObjectMapper();
            // 전체 ResponseEntity 객체를 JSON 문자열로 변환.
            ResponseEntity responseEntity = ResponseData.toResponseEntity(ResponseCode.LOGIN_SUCCESS, oAuthLoginResponseDto);
            String jsonString = objectMapper.writeValueAsString(responseEntity);
            // 위의 JSON 문자열에서 "body" 필드만 추출.
            JsonNode rootNode = objectMapper.readTree(jsonString);
            JsonNode dataNode = rootNode.path("body");
            String jsonData = objectMapper.writeValueAsString(dataNode);

            response.getWriter().write(jsonData);

        } catch (Exception e) {
            throw e;
        }
    }
}


//@Slf4j
//@Component
//@RequiredArgsConstructor
//public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {
//
//    private final TokenProvider tokenProvider;
//
//
//    @Override
//    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//        log.info("OAuth2 Login 성공!");
//
//        try {
//            CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();
//
//            TokenDto tokenDto = tokenProvider.generateTokenDto(authentication);  // Access 토큰 발행.
//            String accessToken = tokenDto.getAccessToken();
//            log.info("발급된 Access Token : {}", accessToken);
//
//            response.setStatus(HttpServletResponse.SC_OK);
//            response.setContentType("application/json;charset=UTF-8");
//
//            OAuthLoginResponseDto oAuthLoginResponseDto = new OAuthLoginResponseDto();
//            oAuthLoginResponseDto.setTokenDto(tokenDto);
//
//            // 최종 응답 JsonObject 생성 (ResponseEntity 처럼)
//            JsonObject jsonResponse = new JsonObject();
//            jsonResponse.addProperty("status", ResponseCode.LOGIN_SUCCESS.getHttpStatus());
//            jsonResponse.addProperty("message", ResponseCode.LOGIN_SUCCESS.getMessage());
//            jsonResponse.addProperty("code", ResponseCode.LOGIN_SUCCESS.name());
//            jsonResponse.addProperty("timestamp", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy. M. d. a h:mm").withLocale(Locale.forLanguageTag("ko"))));
//
//            if(oAuth2User.getRole().equals(Role.GUEST)) {  // User의 Role이 GUEST일 경우, 처음 요청한 회원이므로, 회원가입 페이지로 리다이렉트 시켜야함을 프론트에 전달.
//                oAuthLoginResponseDto.setIsNewUser(true);
//                oAuthLoginResponseDto.setRedirectMessage("신규 회원 입니다. JWT 헤더를 가진채로, 추가정보 입력을 위한 회원가입 페이지로 리다이렉트 시켜주세요.");
//            } else {  // 이미 한 번 이상 OAuth2 로그인했던 유저일 때 (즉, 이미 회원가입 추가정보를 입력해두었던 유저일때)
//                oAuthLoginResponseDto.setIsNewUser(false);
//                oAuthLoginResponseDto.setRedirectMessage("기존 회원 입니다. JWT 헤더를 가진채로, 메인 페이지로 리다이렉트 시켜주세요.");
//            }
//
//                Gson gson = new GsonBuilder().create();
//                // OAuthLoginResponseDto 객체를 JSON으로 변환
//                String dtoJson = gson.toJson(oAuthLoginResponseDto);
//                JsonObject dtoJsonObject = gson.fromJson(dtoJson, JsonObject.class);
//                jsonResponse.add("data", dtoJsonObject);  // 변환된 oAuthLoginResponseDto인 JsonObject를 추가.
//
//                response.getWriter().write(jsonResponse.toString());
//
//        } catch (Exception e) {
//            throw e;
//        }
//    }
//}


//@Slf4j
//@Component
//@RequiredArgsConstructor
//public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {
//
//    private final TokenProvider tokenProvider;
//
//
//    @Override
//    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//        log.info("OAuth2 Login 성공!");
//
//        try {
//            CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();
//
//            TokenDto tokenDto = tokenProvider.generateTokenDto(authentication);  // Access 토큰 발행.
//            String accessToken = tokenDto.getAccessToken();
//            log.info("발급된 Access Token : {}", accessToken);
//
//            response.setStatus(HttpServletResponse.SC_OK);
//            response.setContentType("application/json;charset=UTF-8");
//
//            // TokenDto 객체를 JSON으로 변환
//            Gson gson = new GsonBuilder().create();
//            String tokenDtoJson = gson.toJson(tokenDto);
//            JsonObject tokenDtoJsonObject = gson.fromJson(tokenDtoJson, JsonObject.class);
//
//            // 최종 응답 JsonObject 생성
//            JsonObject jsonResponse = new JsonObject();
//            jsonResponse.add("tokenDto", tokenDtoJsonObject);  // 변환된 tokenDto인 JsonObject를 추가.
//
//            if(oAuth2User.getRole().equals(Role.GUEST)) {  // User의 Role이 GUEST일 경우, 처음 요청한 회원이므로, 회원가입 페이지로 리다이렉트 시켜야함을 프론트에 전달.
//                jsonResponse.addProperty("isNewUser", true);
//                jsonResponse.addProperty("message", "신규 회원 입니다. JWT 헤더를 가진채로, 추가정보 입력을 위한 회원가입 페이지로 리다이렉트 시켜주세요.");
//                response.getWriter().write(jsonResponse.toString());
//            } else {  // 이미 한 번 이상 OAuth2 로그인했던 유저일 때 (즉, 이미 회원가입 추가정보를 입력해두었던 유저일때)
//                jsonResponse.addProperty("isNewUser", false);
//                jsonResponse.addProperty("message", "기존 회원 입니다. JWT 헤더를 가진채로, 메인 페이지로 리다이렉트 시켜주세요.");
//                response.getWriter().write(jsonResponse.toString());
//            }
//        } catch (Exception e) {
//            throw e;
//        }
//    }
//}