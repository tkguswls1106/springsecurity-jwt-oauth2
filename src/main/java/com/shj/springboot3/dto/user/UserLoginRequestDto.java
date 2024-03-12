package com.shj.springboot3.dto.user;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

@Getter
@NoArgsConstructor
public class UserLoginRequestDto {

    private String loginId;
    private String firstPw;

    @Builder
    public UserLoginRequestDto(String loginId, String firstPw) {
        this.loginId = loginId;
        this.firstPw = firstPw;
    }


    // UsernamePasswordAuthenticationToken을 반환하여 차후 이 객체를 이용하여 아이디와 비밀번호가 일치하는지 검증하는 로직을 사용할 예정이다.
    public UsernamePasswordAuthenticationToken toAuthentication() {
        return new UsernamePasswordAuthenticationToken(loginId, firstPw);
    }
}
