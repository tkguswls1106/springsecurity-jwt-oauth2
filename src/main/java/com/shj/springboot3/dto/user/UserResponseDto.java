package com.shj.springboot3.dto.user;

import com.shj.springboot3.domain.user.User;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class UserResponseDto {  // 요청받아 가져오는 DTO. 예를들어 CRUD의 R. method로는 get.
    // 일반적인 용도의, 사용자 정보를 가져오는 ResponseDto

    private Long id;
    private String loginId;
    private String username;

//    // DB에서 repository를 통해 조회하거나 가져온 entity(도메인)를 dto로 변환 용도
//    public UserResponseDto(User entity) {
//        this.id = entity.getId();
//        this.loginId = entity.getLoginId();
//        this.username = entity.getUsername();
//    }
}
