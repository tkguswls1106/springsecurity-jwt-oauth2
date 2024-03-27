package com.shj.springboot3.dto.user;

import com.shj.springboot3.domain.user.User;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class UserUpdateNameRequestDto {  // 요청하는 DTO. 예를들어 CRUD의 C. method로는 post.
    // 사용자 이름 수정 전용의 RequestDto

    private String username;

    @Builder
    public UserUpdateNameRequestDto(String username) {
        this.username = username;
    }

//    // 클라이언트에게 받아왔고 계층간 이동에 사용되는 dto를 DB에 접근할수있는 entity로 변환 용도
//    public User toEntity() {
//        return User.UserUpdateNameBuilder()
//                .username(username)
//                .build();
//    }
}