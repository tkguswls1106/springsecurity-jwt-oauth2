package com.shj.springboot3.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.shj.springboot3.jwt.TokenProvider;
import com.shj.springboot3.oauth.CustomOAuth2UserService;
import com.shj.springboot3.oauth.handler.OAuth2LoginFailureHandler;
import com.shj.springboot3.oauth.handler.OAuth2LoginSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity  // Spring Security 설정을 활성화시키는 어노테이션
@Component
public class WebSecurityConfig {  // 스프링 시큐리티 구성요소 설정 클래스 (JWT 사용지원을 위한 구성 또한 포함)

    private final TokenProvider tokenProvider;
    private final ObjectMapper objectMapper;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    private final OAuth2LoginFailureHandler oAuth2LoginFailureHandler;


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {  // HTTP 보안 설정을 구성하는 메소드
        http
                .httpBasic(httpBasic -> {
                    httpBasic.disable();
                })
                .csrf(csrf -> {
                    csrf.disable();
                })
                .sessionManagement((sessionManagement) -> {
                    sessionManagement
                            .sessionCreationPolicy(SessionCreationPolicy.STATELESS);  // 세션관리 정책을 STATELESS(세션이 있으면 쓰지도 않고, 없으면 만들지도 않는다)
                })

                .authorizeHttpRequests((authorizeRequests) ->
                        authorizeRequests
                                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                                .requestMatchers("/**").permitAll()  // 임시 테스팅 용도
                                // .requestMatchers("/", "/login", "/oauth2/signup").permitAll()
                                .anyRequest().authenticated()
                )

                .oauth2Login(oauth2 -> oauth2
                        .successHandler(oAuth2LoginSuccessHandler)
                        .failureHandler(oAuth2LoginFailureHandler)
                        .userInfoEndpoint(userInfoEndpointConfig -> userInfoEndpointConfig  // userInfoEndpoint란, oauth2 로그인 성공 후 설정을 시작한다는 말이다.
                                .userService(customOAuth2UserService)))  // OAuth2 로그인시 사용자 정보를 가져오는 엔드포인트와 사용자 서비스를 설정.

                .apply(new JwtSecurityConfig(tokenProvider, objectMapper));
                // JwtSecurityConfig와 같은 보안 구성 클래스는 WebSecurityConfig 클래스 내에서 .apply() 메서드를 통해 명시적으로 적용하기때문에, JwtSecurityConfig에 @Configuration 어노테이션을 붙이지않아도된다.

        return http.build();
    }
}