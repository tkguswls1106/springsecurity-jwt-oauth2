package com.shj.springboot3.service.impl;

import com.shj.springboot3.domain.user.Role;
import com.shj.springboot3.domain.user.User;
import com.shj.springboot3.domain.user.UserRepository;
import com.shj.springboot3.dto.auth.ReissueRequestDto;
import com.shj.springboot3.dto.auth.TokenDto;
import com.shj.springboot3.jwt.TokenProvider;
import com.shj.springboot3.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private final UserRepository userRepository;
    private final TokenProvider tokenProvider;


    @Transactional
    @Override
    public TokenDto reissue(ReissueRequestDto reissueRequestDto) {  // Refresh Token으로 Access Token 재발급 메소드

        // RequestDto로 전달받은 Token값들
        String accessToken = reissueRequestDto.getAccessToken();
        String refreshToken = reissueRequestDto.getRefreshToken();

        // Refresh Token 유효성 검사
        if(tokenProvider.validateToken(refreshToken) == false) {
            throw new RuntimeException("입력한 Refresh Token은 잘못된 토큰입니다.");
        }

        // Access Token에서 userId 가져오기
        Authentication authentication = tokenProvider.getAuthentication(accessToken);
        Long userId = Long.valueOf(authentication.getName());

        // userId로 사용자 검색 & 해당 사용자의 role 가져오기
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("해당 사용자는 존재하지 않습니다."));
        Role role = user.getRole();

        // DB의 사용자 Refresh Token 값과, 전달받은 Refresh Token의 불일치 여부 검사
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
