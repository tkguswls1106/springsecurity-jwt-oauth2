package com.shj.springboot3.controller;

import com.shj.springboot3.domain.user.User;
import com.shj.springboot3.domain.user.UserRepository;
import com.shj.springboot3.dto.user.UserResponseDto;
import com.shj.springboot3.response.ResponseCode;
import com.shj.springboot3.response.ResponseData;
import com.shj.springboot3.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", allowedHeaders = "*")
@RestController
@RequiredArgsConstructor
public class TestController {

    private final UserRepository userRepository;


    // Test API
    @GetMapping("/test")  // 이 api는 헤더에 JWT토큰이 반드시 필요하다. (헤더의 토큰을 없애며 테스트 진행하기.)
    public ResponseEntity test() {
        Long userId = SecurityUtil.getCurrentMemberId();
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("해당 사용자는 존재하지 않습니다."));
        return ResponseData.toResponseEntity(ResponseCode.HEALTHY_SUCCESS, new UserResponseDto(user));
    }
}
