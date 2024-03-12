package com.shj.springboot3.dto.user;

import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
public class UserRequestDtos {  // 요청하는 DTO. 예를들어 CRUD의 C. method로는 post.
    // 일반적인 용도의, 사용자 정보를 전달해주는 RequestDto

    private List<UserRequestDto> userRequestDtos;
}
