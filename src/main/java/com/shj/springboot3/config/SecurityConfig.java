package com.shj.springboot3.config;

import com.shj.springboot3.jwt.JwtFilter;
import com.shj.springboot3.jwt.TokenProvider;
import com.shj.springboot3.jwt.handler.JwtAccessDeniedHandler;
import com.shj.springboot3.jwt.handler.JwtAuthenticationEntryPoint;
import com.shj.springboot3.oauth.CustomOAuth2UserService;
import com.shj.springboot3.oauth.handler.OAuth2LoginFailureHandler;
import com.shj.springboot3.oauth.handler.OAuth2LoginSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity  // Spring Security 설정을 활성화시키는 어노테이션
@Component
public class SecurityConfig {  // 스프링 시큐리티 구성요소 설정 클래스 (JWT 사용지원을 위한 구성 또한 포함)

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    private final OAuth2LoginFailureHandler oAuth2LoginFailureHandler;


//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {  // HTTP 보안 설정을 구성하는 메소드
        http
                .httpBasic(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .sessionManagement(sessionManagement -> {
                    sessionManagement
                            .sessionCreationPolicy(SessionCreationPolicy.STATELESS);  // 세션관리 정책을 STATELESS(세션이 있으면 쓰지도 않고, 없으면 만들지도 않는다)
                })

                .authorizeHttpRequests(authorizeRequests -> {
                    authorizeRequests
                            .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
//                            .requestMatchers("/**").permitAll()  // 임시 테스팅 용도
                            .requestMatchers("/", "/error", "/favicon.ico", "/login").permitAll()
                            .anyRequest().authenticated();
                })

                .exceptionHandling(exceptionHandling -> {
                    exceptionHandling
                            .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                            .accessDeniedHandler(jwtAccessDeniedHandler);
                })

                .oauth2Login(oauth2 -> {
                        oauth2
                        .successHandler(oAuth2LoginSuccessHandler)
                        .failureHandler(oAuth2LoginFailureHandler)
                        .userInfoEndpoint(userInfoEndpointConfig -> {
                            userInfoEndpointConfig  // userInfoEndpoint란, oauth2 로그인 성공 후 설정을 시작한다는 말이다.
                                    .userService(customOAuth2UserService);  // OAuth2 로그인시 사용자 정보를 가져오는 엔드포인트와 사용자 서비스를 설정.
                        });
                })

                .addFilterBefore(new JwtFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class);

        // - 전체적인 순서: JwtFilter -> JwtAuthenticationEntryPoint
        // - 토큰 만료시 순서: JwtFilter -> JwtFilter 내의 tokenProvider 에서 '토큰 만료' 로그 출력 -> JwtFilter 내의 filterChain.doFilter(request, response); 실행 -> JwtAuthenticationEntryPoint 에서 401
        // - 토큰 헤더에 미탑재시 순서: JwtFilter -> JwtFilter 내의 filterChain.doFilter(request, response); 실행 -> JwtAuthenticationEntryPoint 에서 401

        return http.build();
    }
}