package com.shj.springboot3.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@Slf4j
public class SecurityUtil {

    private SecurityUtil() { }

    public static Long getCurrentMemberId() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || authentication.getName() == null) {
            throw new RuntimeException("Security Context에 인증 정보가 없습니다.");
        }

        return Long.parseLong(authentication.getName());  // 여기에 getName의 Name은 로그인계정아이디가 아닌, 사용자DB의PKid를 String형식으로 넣어뒀던것이다.
    }
}