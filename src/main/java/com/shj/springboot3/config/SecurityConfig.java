package com.shj.springboot3.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.shj.springboot3.jwt.JwtExceptionFilter;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity  // Spring Security 설정을 활성화시키는 어노테이션
@Component
public class SecurityConfig {  // 스프링 시큐리티 구성요소 설정 클래스 (JWT 사용지원을 위한 구성 또한 포함)

    private final TokenProvider tokenProvider;
    private final ObjectMapper objectMapper;
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
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                .authorizeHttpRequests(authorizeRequests -> {
                    authorizeRequests
                            // 설정 시에, 구체적인 경로인 작은 범위부터 먼저 위에 오고, 그보다 큰 범위의 경로가 아래에 오도록 작성해야한다. 이는 시큐리티가 위에서 아래로 해석을 하기 때문이다.
                            // 아마도 위의 것부터 적용이 먼저되는듯 하다.
                            // 참고로 permitAll()은 filter 접근과는 무관하다. permitAll()을 적용해도 filter을 지나친다. 이와 관련한 shouldNotFilter() 및 추가 설명은 따로 맨밑에 주석으로 작성해두었음.

                            .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()  // 이 구문은 주로 CORS 사전 요청 처리를 위해 사용되므로, 보안 설정의 초기 부분에 위치하는 것이 일반적이다.
                            .requestMatchers(HttpMethod.POST, "/oauth2/signup").hasAuthority("ROLE_GUEST")  // 참고로 이는 DB뿐만이 아니라, 헤더의 jwt 토큰에 등록해둔 권한도 바꾸어 재발급 받아야 한다.

//                            .requestMatchers("/**").permitAll()  // 임시 테스팅 용도
                            .requestMatchers("/", "/error", "/favicon.ico", "/reissue").permitAll()

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

                .addFilterBefore(new JwtFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JwtExceptionFilter(objectMapper), JwtFilter.class);

        // - 전체적인 순서: request 요청 -> JwtExceptionFilter -> JwtFilter -> JwtAuthenticationEntryPoint(401) or JwtExceptionFilter
        // - permitAll()없이 토큰없이 로그인필수기능 이용하려고 할시 순서: request 요청 -> JwtExceptionFilter -> JwtFilter -> JwtAuthenticationEntryPoint 에서 401
        // - 토큰 만료시 순서: request 요청 -> JwtExceptionFilter -> JwtFilter -> JwtExceptionFilter

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOriginPatterns(Arrays.asList("http://localhost:3000"));
        config.setAllowedHeaders(Arrays.asList("*"));
        config.setAllowedMethods(Arrays.asList("*"));
        config.setAllowCredentials(true);

//        config.addAllowedOrigin("http://localhost:3000");
//        config.addAllowedHeader("*");
//        config.addAllowedMethod("*");
//        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}

/*
[ SecurityConfig의 permitAll()과, jwt Filter의 shouldNotFilter()에 대한 총정리 ]

< SecurityConfig의 permitAll() 설명 >
- 헤더에 인증정보(JWT토큰)가 안달린채로 api 호출이 오고, 차후 모든 filter를 처리한 후에도 SecurityContext에 등록된 인증 정보가 없더라도 접근을 허용하게 해주는 것이다.
- 이는 특정 url이 filter를 타지 않도록 설정 하는것이 아니다. 즉, jwt filter의 접근 통과 여부와는 전혀 무관한 설정인 것이다.
- 따라서 permitAll()로 해당 url을 지정해두었다 한들, filter 구성 중 특정 조건에서 Exception(예를들어 만료exception)을 던지는 부분이 있다면, permitAll()을 한 것과는 상관 없이 에러가 잡히게 된다.
- 그래서 혹여나 만약 헤더에 토큰이 달렸는지 안달렸는지 확정이 되지않은 경우인데, filter 접근해서 토큰 만료같은 검사없이 바로 컨트롤러로 그대로 이동되어야 한다면,
- 그래서 만약 filter에 도착하게된 경우 중에서, reissue처럼 토큰 만료같은 검사없이 바로 전달되어야하는경우, 헤더에 jwt 토큰을 안달았을뿐더러, filter에서 shouldNotFilter()을 사용해주어야만 한다.

< 헤더의 토큰 여부가 있는지없는지 모를때 && permitAll()해둔 url인 경우 && 하지만 shouldNotFilter에 등록을 안한 url인 경우 >
일단 request 접근 허용은 됨 -> filter 진입 -> filter에 작성해둔 exeption에 걸릴 수 있음. 만료토큰이면 예외처리됨.
그래서 reissue나 login request처럼 로그인이 필요없는 api url처럼 헤더에 토큰이 필요없는 url임에도 불구하고, 프론트엔드에서 실수로 토큰을 헤더에 함께 담아 전송한 경우에,
만약 해당 헤더의 토큰이 만료된경우 filter에서 만료exception에 걸려서 예외 처리로 걸리게 되는것이다. 그래서 만료된 토큰을 재발급 하고자했지만, 오히려 만료 토큰으로 예외처리되어 재발급을 못받는 불상사가 생길 수 있다.
==>
헤더에 토큰이 있든 없든, 있어도 해당 토큰이 만료가 됐든 말든 간에, 상관없이 반드시 api를 호출 가능하게 해야한다 => permitAll() & shouldNotFilter() 둘다 사용.
헤더에 토큰이 있든 없든 상관없지만, 있다면 해당 토큰이 만료가 되면 만료exception처리를 해주어야만 한다 => permitAll() 하나만 사용. shouldNotFilter() 사용X.
헤더에 토큰이 반드시 있어야하지만, 해당 토큰이 만료가 됐든 말든 간에, 상관없이 반드시 api를 호출 가능하게 해야한다 => shouldNotFilter() 하나만 사용. permilAll() 사용X.
헤더에 토큰이 반드시 있어야하고, 해당 토큰이 만료가 되면 만료exception처리를 해주어야만 한다 => 둘다 사용X.

< 프론트엔드 팀원이, 상황에 맞추어 헤더에 토큰을 넣고 빼가며 알맞게 api요청보내는 사람일때 [추천/정석] >
이러한 프론트엔드와 함께인 경우, 로그인 필요없는 기능 api 호출시, shouldNotFilter()없이 permitAll()만 해두었어도, 어차피 헤더에 토큰이 존재하지않아 토큰값이 null이 되어, filter에 접근해도 StringUtils.hasText(jwt)=false로써 어차피 여기서 걸려져서, 토큰만료exception검사 없이 바로 filterChain.doFilter()로 filter을 그대로 지나가게 된다. (즉, permitAll()만 해두어도, 어차피 토큰 만료검사를 안하고 지나치치기 가능.)
- 로그인 필수 기능: 둘다 사용X.
- 로그인 필요없는 기능: permitAll() 하나만 사용. shouldNotFilter() 사용X.
< 프론트엔드 팀원이, 무슨 경우든간에 일단 헤더에 토큰을 넣고 api요청보내는 사람일때 [비추천] >
- 로그인 필수 기능: 둘다 사용X.
- 로그인 필요없는 기능: permitAll() & shouldNotFilter() 둘다 사용.
< 위 요약정리 >
- 로그인 필수 기능 api 호출시 => 둘다 사용X.
- 로그인 필요없는 기능 api를 호출하는데, 요청 헤더에 토큰이 없다는 것이 확정된 경우 => permitAll() 하나만 사용. shouldNotFilter() 사용X.
- 로그인 필요없는 기능 api를 호출하는데, 요청 헤더에 토큰이 없다는 것이 확정되지 않은 경우 => permitAll() & shouldNotFilter() 둘다 사용.
==> 추천: 프론트엔드에서 jwt헤더를 알맞게 잘관리해서 api요청을 보내주면 된다. 그러면 사실상 shouldNotFilter()는 사용할 경우가 없을것이다.
 */