package com.shj.springboot3.controller;

import com.shj.springboot3.dto.token.TokenDto;
import com.shj.springboot3.dto.user.*;
import com.shj.springboot3.response.ResponseCode;
import com.shj.springboot3.response.ResponseData;
import com.shj.springboot3.service.auth.AuthService;
import com.shj.springboot3.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*", allowedHeaders = "*")
@RestController
@RequiredArgsConstructor  // 이걸로 private final 되어있는걸 자동으로 생성자 만들어줘서 @Autowired와 this 없이 의존관계 DI 주입시켜줌.
public class AuthController {
    // < 로그인되어있는지 여부 확인의 전체적인 로직 >
    // 로그인없이는 이용할수없는 api가 컨트롤러단에서 호출됨.
    // -> JwtFilter가 HTTP 요청을 가로채서 JWT 토큰이 있는지 확인.
    // -> JwtFilter의 resolveToken 메소드: 토큰 존재 확인 후 문자열로 토큰 추출.
    // -> JwtFilter의 doFilterInternal 메소드: 추출된 토큰 문자열의 유효성 검사.
    // -> JwtFilter의 doFilterInternal 메소드: 추출된 토큰 문자열로 사용자 인증(비밀번호 체킹없이, 단지 JWT토큰의 계정아이디에 대한 정보가 시스템DB에 일치하는 정보가 있는지 확인하고 권한 또한 확인).
    // -> JwtFilter의 doFilterInternal 메소드: Spring Security의 SecurityContextHolder에 인증 정보를 설정.
    // -> JwtFilter의 doFilterInternal 메소드: 현재 필터의 작업이 끝난 후, 다음 필터로 HTTP 요청을 전달.
    // < 로그인 로직 >
    // login api가 컨트롤러단에서 호출됨. (이는 jwt 헤더검사 절차 없이 진행하도록 설정하므로, JwtFilter가 HTTP 요청을 가로채지 않음.)
    // -> 서비스단의 login메소드: input한 로그인 정보로 UsernamePasswordAuthenticationToken 생성.
    // -> 서비스단의 login메소드: AuthenticationManagerBuilder에서 managerBuilder.getObject()를 통해 AuthenticationProvider 사용. 그리고 UsernamePasswordAuthenticationToken를 파라미터로 넣음.
    // -> 서비스단의 login메소드: AuthenticationProvider가 UserDetailsService 인터페이스를 상속받는 CustomDetailsService를 참조하여, DB에서 일치되는 사용자 정보를 꺼내와 UserDetails 객체로 변환하여 가져옴.
    // -> 서비스단의 login메소드: 'AuthenticationProvider에 파라미터로 넣어준 UsernamePasswordAuthenticationToken 인증토큰객체'와 'DB에서 가져온 UserDetails 객체'에 대하여 사용자 아이디+비밀번호를 일치하는지 체킹함.
    // -> 일치 성공하면 예외처리 발생없이 정상적으로 토큰을 generateTokenDto()메소드로 발행시켜 프론트엔드에게 반환해줌.

    private final AuthService authService;


    @GetMapping("/auth")
    public ResponseEntity isLogin() {  // 로그인 상태 여부 확인
        Long userId = SecurityUtil.getCurrentMemberId();
        UserIdResponseDto userIdResponseDto = new UserIdResponseDto(userId);

        return ResponseData.toResponseEntity(ResponseCode.READ_IS_LOGIN, userIdResponseDto);
    }

    @PostMapping("/signup")
    public ResponseEntity joinUser(@RequestBody UserSignupRequestDto userSignupRequestDto) {  // 회원가입
        UserResponseDto userResponseDto = authService.signup(userSignupRequestDto);
        return ResponseData.toResponseEntity(ResponseCode.CREATED_USER, userResponseDto);
    }

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody UserLoginRequestDto userLoginRequestDto) {  // 로그인
        TokenDto tokenDto = authService.login(userLoginRequestDto);
        return ResponseData.toResponseEntity(ResponseCode.LOGIN_SUCCESS, tokenDto);
    }

    @GetMapping("/login")
    public ResponseEntity getLogin() {  // 로그인 api가 get방식으로 요청올시에
        return ResponseData.toResponseEntity(ResponseCode.GET_LOGIN);
    }

    @PutMapping("/password")
    public ResponseEntity updatePassword(@RequestBody UserUpdatePwRequestDto userUpdatePwRequestDto) {  // 비밀번호 수정
        authService.updatePw(userUpdatePwRequestDto);
        return ResponseData.toResponseEntity(ResponseCode.UPDATE_PASSWORD);
    }
}