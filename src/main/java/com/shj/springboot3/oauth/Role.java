package com.shj.springboot3.oauth;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Role {

    // 처음 로그인하는 유저를 Role.GUEST로 설정.
    // 이후에 추가 정보를 입력해서 회원가입을 진행하면, Role.USER로 업데이트하는 식으로 설정.
    // 이렇게 하면, OAuth 로그인 회원 중 Role.GUEST인 회원은 처음 로그인이므로, SuccessHandler에서 추가 데이터 정보를 입력하는 URL로 리다이렉트한다.
    // 이후에 OAuth2LoginSuccessHandler에서 해당 이메일로 Token 발급 & 처리.
    GUEST("ROLE_GUEST"), USER("ROLE_USER");  // getRole().getKey() 응용 가능.

    private final String key;
}