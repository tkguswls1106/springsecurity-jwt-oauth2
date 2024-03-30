package com.shj.springboot3.service;

import com.shj.springboot3.dto.auth.ReissueRequestDto;
import com.shj.springboot3.dto.auth.TokenDto;

public interface TokenService {

    TokenDto reissue(ReissueRequestDto reissueRequestDto);
    void updateRefreshToken(Long userId, String refreshToken);
}
