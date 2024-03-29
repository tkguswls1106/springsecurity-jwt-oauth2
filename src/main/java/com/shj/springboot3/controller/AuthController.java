package com.shj.springboot3.controller;

import com.shj.springboot3.dto.auth.SignupResponseDto;
import com.shj.springboot3.dto.user.UserResponseDto;
import com.shj.springboot3.dto.user.UserSignupRequestDto;
import com.shj.springboot3.response.ResponseCode;
import com.shj.springboot3.response.ResponseData;
import com.shj.springboot3.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*", allowedHeaders = "*")
@RestController
@RequiredArgsConstructor  // 이걸로 private final 되어있는걸 자동으로 생성자 만들어줘서 @Autowired와 this 없이 의존관계 DI 주입시켜줌.
public class AuthController {
    // < 로그인되어있는지 여부 확인의 전체적인 로직 >
    // 로그인없이는 이용할수없는 api가 컨트롤러단에서 호출됨.
    // -> JwtFilter가 HTTP 요청을 가로채서 JWT 토큰이 있는지 확인. 그러기위해선 밑의 과정 필요.
    // -> JwtFilter가 doFilterInternal 메소드를 실행.
    // -> JwtFilter의 resolveToken 메소드: 토큰 존재 확인 후 문자열로 토큰 추출.
    // -> JwtFilter의 doFilterInternal 메소드: 추출된 토큰 문자열의 유효성 검사.
    // -> JwtFilter의 doFilterInternal 메소드: 추출된 토큰 문자열로 사용자 인증(비밀번호 체킹없이, 단지 JWT토큰의 Payload에 담긴 name인 사용자DB의PKid가 실제 DB에 일치하는 정보가 있는지 확인하고 권한 또한 확인).
    // -> JwtFilter의 doFilterInternal 메소드: Spring Security의 SecurityContextHolder에 인증 정보를 설정.
    // -> JwtFilter의 doFilterInternal 메소드: 현재 필터의 작업이 끝난 후, 다음 필터로 HTTP 요청을 전달.
    // < 로그인 로직 >
    // login api가 컨트롤러단에서 호출됨. ('/login'은 jwt 헤더검사 절차 없이 진행하도록 설정하므로, JwtFilter가 HTTP 요청을 가로채지 않음.)
    // -> 서비스단의 login 메소드: input한 로그인정보(로그인계정아이디,비밀번호)로 UsernamePasswordAuthenticationToken 생성.
    // -> 서비스단의 login 메소드: AuthenticationManagerBuilder에서 managerBuilder.getObject()를 통해 AuthenticationProvider 사용. 그리고 '로그인계정아이디,비밀번호'를 담은 UsernamePasswordAuthenticationToken를 파라미터로 넣음.
    // -> 서비스단의 login 메소드: AuthenticationProvider가 자동으로 UserDetailsService 인터페이스를 상속받는 CustomDetailsService를 참조.
    // -> CustomUserDetailsService의 loadUserByUsername 메소드: 'AuthenticationProvider에 파라미터로 넣어준 UsernamePasswordAuthenticationToken'의 로그인계정아이디와 일치하는 사용자가 DB에 존재하는지 확인.
    // -> CustomUserDetailsService의 createUserDetails 메소드: 확인된 DB User객체의 '사용자DB의PKid,비밀번호,권한'을 가지고 UserDetails 객체를 생성.
    // -> CustomUserDetailsService의 createUserDetails 메소드: UserDetails 객체 생성을 위해 진행했던 'new org.springframework.security.core.userdetails.User' 과정에서, SecurityConfig에 등록했던 PasswordEncoder Bean 객체가 비밀번호 일치 체킹을 한다.
    // -> 서비스단의 login 메소드: 결과적으로 'AuthenticationProvider에 파라미터로 넣어준 UsernamePasswordAuthenticationToken 인증토큰객체'와 'DB에서 가져온 UserDetails 객체'에 대하여 사용자 아이디+비밀번호를 일치하는지 체킹함.
    // -> 일치 성공하면 예외처리 발생없이 정상적으로 토큰을 generateTokenDto()메소드로 발행시켜 프론트엔드에게 반환해줌.

    private final AuthService authService;


    // - oauth2signup()으로 해당 성공 ResponseEntity를 반환에 성공한다면, 프론트에서는 이미 헤더에 저장해둔 토큰으로 메인 페이지로 이동시키면됨.
    // 문제점 1. 프론트에서 <a href="/oauth2/authorization/kakao"> 를 어떻게 구현할것인가?
    // (O) 문제점 2. 토큰 만료의 경우를 TokenProvider에서 말고 다른곳에서 처리하는 법은? (JwtAuthenticationEntryPoint 대신 JwtExceptionFilter 로 가능할지도)
    // (O) 문제점 3. 토큰 만료의 경우를 걸러냈다치고, 이럴때 리프레쉬 토큰을 재설정해서 프론트에 넘겨주는 법은?
    // (O) 문제점 4. '/oauth2/signup'는 Role.GUEST만, 나머지 api url은 전부 Role.USER 또는 Role.ADMIN 만 사용가능하도록, .requestMatchers 설정하는 법은?
    // 문제점 5. login api와 signup api의 구분은 정확히 어떻게 할것이며 그러한 플로우는 어떻게 진행할것인가?
    // 문제점 6. '.requestMatchers("/**").permitAll()' 이거 없이 어떻게 초반 oauth 로그인을 진행할것인가?
    @PostMapping("/oauth2/signup")  // 이 api는 헤더에 JWT토큰이 반드시 필요하다.
    public ResponseEntity signup(Authentication authentication, @RequestBody UserSignupRequestDto userSignupRequestDto) {  // 여기서 Role을 USER로 교체해주지 않으면 다른 로그인 필수 api를 사용하지 못한다.
        SignupResponseDto signupResponseDto = authService.signup(userSignupRequestDto);
        return ResponseData.toResponseEntity(ResponseCode.CREATED_USER, signupResponseDto);
    }

    @GetMapping("/test")  // 이 api는 헤더에 JWT토큰이 반드시 필요하다. (헤더의 토큰을 없애며 테스트 진행하기.)
    public ResponseEntity test() {
        return ResponseData.toResponseEntity(ResponseCode.HEALTHY_SUCCESS);
    }
}