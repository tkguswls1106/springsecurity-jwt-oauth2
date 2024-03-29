package com.shj.springboot3.service.impl;

import com.shj.springboot3.domain.user.Role;
import com.shj.springboot3.domain.user.User;
import com.shj.springboot3.domain.user.UserRepository;
import com.shj.springboot3.dto.auth.TokenDto;
import com.shj.springboot3.jwt.TokenProvider;
import com.shj.springboot3.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private final UserRepository userRepository;
    private final TokenProvider tokenProvider;


    @Transactional
    @Override
    public TokenDto reissue(Long userId, String bearerToken) {  // Refresh Token으로 Access Token 재발급 메소드
        // 이미 Refresh Token에 대한 유효성 검사는 filter에서 완료된 상태로 왔기때문에, 유효성 검사는 다시 진행하지 않아도 된다.

        String refreshToken = null;
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {  // 추출된 헤더값이 null이 아닌가 && "Bearer "로 시작하는가 ("Bearer " 다음에 실제 토큰이 오는 것이 관례임.)
            refreshToken = bearerToken.substring(7);  // 토큰이 유효하다면, 앞부분인 "Bearer "을 제외하여 7인덱스부터 끝까지인 실제 토큰 문자열을 반환함.
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("해당 사용자는 존재하지 않습니다."));
        Role role = user.getRole();

        if(userRepository.existsByRefreshToken(refreshToken) == false) {
            throw new RuntimeException("해당 Refresh Token을 가진 사용자는 존재하지 않습니다.");
        }
        if(!user.getRefreshToken().equals(refreshToken)) {
            throw new RuntimeException("잘못된 Refresh Token 입력입니다.");
        }

        TokenDto tokenDto = tokenProvider.generateAccessTokenByRefreshToken(userId, role, refreshToken);
        return tokenDto;
    }

    @Transactional
    @Override
    public void updateRefreshToken(Long userId, String refreshToken) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("해당 사용자는 존재하지 않습니다."));
        user.updateRefreshToken(refreshToken);
    }
}
