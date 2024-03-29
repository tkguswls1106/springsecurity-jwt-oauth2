package com.shj.springboot3.service;

import com.shj.springboot3.domain.user.Role;
import com.shj.springboot3.dto.auth.TokenDto;

public interface TokenService {

//    public TokenDto loginTokenDto(Long userId, Role role);
    public TokenDto generateAccessTokenByRefreshToken(Long userId, Role role, String refreshToken);
    void updateRefreshToken(Long userId, String refreshToken);
}
