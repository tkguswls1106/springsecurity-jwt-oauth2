package com.shj.springboot3.dto.user;

import com.shj.springboot3.domain.user.User;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class UserRequestDto {  // 요청하는 DTO. 예를들어 CRUD의 C. method로는 post.
    // 일반적인 용도의, 사용자 정보를 전달해주는 RequestDto

    private Long id;
    private String loginId;
    private String username;

    @Builder
    public UserRequestDto(Long id, String loginId, String username) {
        this.id = id;
        this.loginId = loginId;
        this.username = username;
    }

//    // 클라이언트에게 받아왔고 계층간 이동에 사용되는 dto를 DB에 접근할수있는 entity로 변환 용도
//    public User toEntity() {
//        return User.builder()
//                .id(id)
//                .loginId(loginId)
//                .username(username)
//                .build();
//    }
}
