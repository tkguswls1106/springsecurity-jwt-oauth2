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
                            // 설정 시에, 구체적인 경로인 작은 범위부터 먼저 위에 오고, 그보다 큰 범위의 경로가 아래에 오도록 작성해야한다. 이는 시큐리티가 위에서 아래로 해석을 하기 때문이다.
                            // 아마도 위의 것부터 적용이 먼저되는듯 하다.

                            .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()  // 이 구문은 주로 CORS 사전 요청 처리를 위해 사용되므로, 보안 설정의 초기 부분에 위치하는 것이 일반적이다.
                            .requestMatchers(HttpMethod.POST, "/oauth2/signup").hasAuthority("ROLE_GUEST")  // 참고로 이는 DB뿐만이 아니라, 헤더의 jwt 토큰에 등록해둔 권한도 바꾸어 재발급 받아야 한다.

                            .requestMatchers("/**").permitAll()  // 임시 테스팅 용도
//                            .requestMatchers("/", "/error", "/favicon.ico", "/login").permitAll()

                            .anyRequest().hasAnyAuthority("ROLE_USER", "ROLE_ADMIN");  // permit 지정한 경로들 외에는 전부 USER나 ADMIN 권한이 있어야지 url을 이용 가능하다. (GUEST 불가능)
//                            .anyRequest().authenticated();  // 위의 permitAll()에 등록된 url들을 제외한 나머지 모든 url들에 대해 jwt 인증이 필요함.
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