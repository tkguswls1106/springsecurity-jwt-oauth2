package com.shj.springboot3.service;

import com.shj.springboot3.domain.user.Role;
import com.shj.springboot3.dto.auth.TokenDto;

public interface TokenService {

    TokenDto reissue(Long userId, String bearerToken);
    void updateRefreshToken(Long userId, String refreshToken);
}
