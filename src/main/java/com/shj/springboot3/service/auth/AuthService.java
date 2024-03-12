package com.shj.springboot3.service.auth;

import com.shj.springboot3.domain.user.User;
import com.shj.springboot3.domain.user.UserJpaRepository;
import com.shj.springboot3.dto.token.TokenDto;
import com.shj.springboot3.dto.user.UserLoginRequestDto;
import com.shj.springboot3.dto.user.UserResponseDto;
import com.shj.springboot3.dto.user.UserSignupRequestDto;
import com.shj.springboot3.dto.user.UserUpdatePwRequestDto;
import com.shj.springboot3.jwt.TokenProvider;
import com.shj.springboot3.response.exeption.LoginIdDuplicateException;
import com.shj.springboot3.response.exeption.NoSuchUserException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserJpaRepository userJpaRepository;
    private final AuthenticationManagerBuilder managerBuilder;
    private final PasswordEncoder passwordEncoder;
    private final TokenProvider tokenProvider;


    @Transactional
    public UserResponseDto signup(UserSignupRequestDto userSignupRequestDto) {  // 신규 사용자 생성하고 user 반환 기능.
        // 클라이언트가 요청한, 클라이언트와 교류한 정보니까 RequestDto 형식을 파라미터로 받음.

        String newLoginId = userSignupRequestDto.getLoginId();
        userJpaRepository.findByLoginId(newLoginId)
                .ifPresent(user -> {  // 해당 로그인아이디의 사용자가 이미 존재한다면,
                    throw new LoginIdDuplicateException(newLoginId);  // 회원가입 로그인아이디 중복 예외처리.
                });

        User entity = userJpaRepository.save(userSignupRequestDto.toEntity(passwordEncoder));
        return new UserResponseDto(entity);
    }

    @Transactional
    public TokenDto login(UserLoginRequestDto userLoginRequestDto) {  // 로그인 기능. (로그인 경우에만 AuthenticationProvider를 통해 아이디와 비밀번호 일치 체킹을 진행한다.)

        // UsernamePasswordAuthenticationToken은 input 받은 사용자명(username)과 비밀번호(password)를 갖는 인증 토큰 객체임.
        UsernamePasswordAuthenticationToken authenticationToken = userLoginRequestDto.toAuthentication();

        // ----------
        // managerBuilder.getObject()를 통해 얻은 AuthenticationManager 객체를 사용하여, 앞서 생성한 authenticationToken을 인증하는 역할을 함.
        // 자세히 들여다보면, AuthenticationManager는 필터로부터 인증 처리를 위임받는 클래스로서 내부적으로 AuthenticationProvider를 가지고 있고,
        // AuthenticationProvider는 DB에서 가져온 정보와 input된 정보가 비교되서 체크되는 로직이 포함되어있는 인터페이스이다. 내부적인 로직 설명으로는,
        // AuthenticationProvider가 'UserDetailsService 인터페이스를 상속받는 CustomDetailsService'를 자동으로 참조 및 호출하여, DB에서 사용자 정보를 꺼내와 UserDetails 객체로 변환시킨다.
        // 이렇게 'DB에서 가져온 UserDetails 객체'정보와 'input되어 생성시킨 UsernamePasswordAuthenticationToken 인증토큰객체'정보를 비교해서, 올바른 절차로 생성된 객체가 맞는지 검증하며 아이디와 비밀번호가 모두 일치하는지 체킹한다.
        // ----------
        // 결국 authenticate 메서드는 실제로 사용자의 인증을 시도하고 검증함으로써, 성공할 경우 완전한 Authentication 객체를 반환함.
        // 만약 실패할경우, 자격 증명(사용자 이름 및 비밀번호)이 인증 시스템에서 유효한 사용자와 일치하지 않음을 의미하며, AuthenticationException 예외 처리됨.
        // 이러한 실패는 잘못된 사용자 이름 또는 비밀번호, 비활성화된 사용자 계정, 만료된 자격 증명 등 여러 이유로 발생할 수 있음.
        // 즉, 여기서 실제로 사용자에 대한 자세한 검증이 이루어지며, 아이디와 비밀번호에 대한 일치 체킹은 AuthenticationProvider에서 진행하는 역할이다.
        Authentication authentication = managerBuilder.getObject().authenticate(authenticationToken);  // 이 코드는 다른것들과 다르게, AuthenticationProvider를 사용함 => 실제 아이디 및 비밀번호 검증 체킹함.

        // 파라미터로 전달해주는 authentication은 현재 인증 성공한 사용자를 나타내는 Authentication 객체이다.
        return tokenProvider.generateTokenDto(authentication);
    }

    @Transactional
    public void updatePw(UserUpdatePwRequestDto userUpdatePwRequestDto) {  // 사용자의 비밀번호 수정 기능.

        UserLoginRequestDto userLoginRequestDto = new UserLoginRequestDto(userUpdatePwRequestDto.getLoginId(), userUpdatePwRequestDto.getFirstPw());
        UsernamePasswordAuthenticationToken authenticationToken = userLoginRequestDto.toAuthentication();
        managerBuilder.getObject().authenticate(authenticationToken);  // 여기서 로그인이 가능한지 실제로 검증이 이루어짐. 만약 검증에 실패하면 AuthenticationException 예외 처리됨.

        User entity = userJpaRepository.findByLoginId(userUpdatePwRequestDto.getLoginId()).orElseThrow(
                ()->new NoSuchUserException(String.format("loginId = %s", userUpdatePwRequestDto.getLoginId())));

        entity.updateFirstPw(passwordEncoder.encode(userUpdatePwRequestDto.getNewFirstPw()));
    }
}