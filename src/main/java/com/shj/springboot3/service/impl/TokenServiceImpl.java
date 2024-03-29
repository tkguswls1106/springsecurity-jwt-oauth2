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

@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private final UserRepository userRepository;
    private final TokenProvider tokenProvider;


    @Transactional
    @Override
    public TokenDto generateAccessTokenByRefreshToken(Long userId, Role role, String refreshToken) {

        if(userRepository.existsByRefreshToken(refreshToken) == false) {
            throw new RuntimeException("해당 Refresh Token을 가진 사용자는 존재하지 않습니다.");
        }
        if(tokenProvider.validateToken(refreshToken) == false) {
            throw new RuntimeException("해당 Refresh Token은 유효한 토큰이 아닙니다.");
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
