package com.shj.springboot3.config;

import com.shj.springboot3.jwt.JwtAccessDeniedHandler;
import com.shj.springboot3.jwt.JwtAuthenticationEntryPoint;
import com.shj.springboot3.jwt.TokenProvider;
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
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;


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
                            .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                })

                .exceptionHandling(exceptionHandling -> {
                    exceptionHandling
                            .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                            .accessDeniedHandler(jwtAccessDeniedHandler);
                })

                .authorizeHttpRequests((authorizeRequests) ->
                        authorizeRequests
                                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                                .requestMatchers("/", "/login", "/auth", "/signup").permitAll()
                                .anyRequest().authenticated()
                )

                .apply(new JwtSecurityConfig(tokenProvider));
                // JwtSecurityConfig와 같은 보안 구성 클래스는 WebSecurityConfig 클래스 내에서 .apply() 메서드를 통해 명시적으로 적용하기때문에, JwtSecurityConfig에 @Configuration 어노테이션을 붙이지않아도된다.

        return http.build();
    }
}