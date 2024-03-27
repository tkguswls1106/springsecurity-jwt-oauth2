package com.shj.springboot3.oauth.handler;

import com.shj.springboot3.dto.token.TokenDto;
import com.shj.springboot3.jwt.TokenProvider;
import com.shj.springboot3.oauth.CustomOAuth2User;
import com.shj.springboot3.oauth.Role;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

            TokenDto tokenDto = tokenProvider.generateTokenDto(authentication);  // Access 토큰 발행.
            String accessToken = tokenDto.getAccessToken();
            log.info("발급된 Access Token : {}", accessToken);

            response.setStatus(HttpServletResponse.SC_OK);

            if(oAuth2User.getRole() == Role.GUEST) {  // User의 Role이 GUEST일 경우, 처음 요청한 회원이므로, 회원가입 페이지로 리다이렉트 시킴.
                response.setHeader("Authorization", "Bearer " + accessToken);
                response.sendRedirect("oauth2/signup"); // '프론트의 회원가입 추가 정보 입력 폼으로 리다이렉트'라는 정보를 reponse에 장착시킴.

                // 밑의 주석부분은 차후에, 컨트롤러와 서비스 클래스를 따로 만들어서, 거기에 작성해주자.
//                // 회원가입의 추가정보 입력이 완료되었으므로, Role을 GUEST -> USER로 업데이트 시킴.
//                User findUser = userRepository.findByEmail(oAuth2User.getEmail())
//                                .orElseThrow(() -> new IllegalArgumentException("이메일에 해당하는 유저가 없습니다."));
//                findUser.updateRole();
            } else {  // 이미 한 번 이상 OAuth2 로그인했던 유저일 때 (즉, 이미 회원가입 추가정보를 입력해두었던 유저일때)
                response.setHeader("Authorization", "Bearer " + accessToken);
            }
        } catch (Exception e) {
            throw e;
        }
    }
}