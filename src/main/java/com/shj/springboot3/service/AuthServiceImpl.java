package com.shj.springboot3.service;

import com.shj.springboot3.domain.user.User;
import com.shj.springboot3.domain.user.UserRepository;
import com.shj.springboot3.dto.user.UserResponseDto;
import com.shj.springboot3.domain.user.Role;
import com.shj.springboot3.dto.user.UserSignupRequestDto;
import com.shj.springboot3.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;


    @Transactional
    @Override
    public UserResponseDto signup(UserSignupRequestDto userSignupRequestDto) {
        Long userId = SecurityUtil.getCurrentMemberId();
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("해당 사용자는 존재하지 않습니다."));

        if(!user.getRole().equals(Role.GUEST)  // Role이 GUEST인 사용자만 이용가능한 api 이다.
                || user.getMoreInfo1() != null || user.getMoreInfo2() != null || user.getMoreInfo3() != null) {
            throw new RuntimeException("이미 가입완료 되어있는 사용자입니다.");
        }

        user.updateMoreInfo(userSignupRequestDto);
        user.updateRole();

        return new UserResponseDto(user);
    }
}
