package com.shj.springboot3.dto.user;

import com.shj.springboot3.domain.user.Authority;
import com.shj.springboot3.domain.user.User;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;

@Getter
@NoArgsConstructor
public class UserSignupRequestDto {  // 요청하는 DTO. 예를들어 CRUD의 C. method로는 post.
    // 사용자 회원가입 전용의 RequestDto

    private String loginId;
    private String firstPw;
    private String username;

    @Builder
    public UserSignupRequestDto(String loginId, String firstPw, String username) {
        this.loginId = loginId;
        this.firstPw = firstPw;
        this.username = username;
    }

    // 클라이언트에게 받아왔고 계층간 이동에 사용되는 dto를 DB에 접근할수있는 entity로 변환 용도
    public User toEntity(PasswordEncoder passwordEncoder) {
        return User.UserJoinBuilder()
                .loginId(loginId)
                .firstPw(passwordEncoder.encode(firstPw))
                .username(username)
                .authority(Authority.ROLE_USER)
                .build();
    }
}
