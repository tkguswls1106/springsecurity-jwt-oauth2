package com.shj.springboot3.service;

import com.shj.springboot3.dto.user.UserResponseDto;
import com.shj.springboot3.dto.user.UserSignupRequestDto;

public interface AuthService {

    UserResponseDto signup(UserSignupRequestDto userSignupRequestDto);
}
