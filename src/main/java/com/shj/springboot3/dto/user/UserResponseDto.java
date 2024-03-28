package com.shj.springboot3.dto.user;

import com.shj.springboot3.domain.user.User;
import com.shj.springboot3.domain.user.SocialType;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Getter
@NoArgsConstructor
public class UserResponseDto {  // 요청받아 가져오는 DTO. 예를들어 CRUD의 R. method로는 get.
    // 일반적인 용도의, 사용자 정보를 가져오는 ResponseDto

    private Long id;
    private String email;

    private String nickname;
    private String imageUrl;
    private SocialType socialType;

    private LocalDateTime createdTime;

    private String moreInfo1;
    private String moreInfo2;
    private String moreInfo3;

    // DB에서 repository를 통해 조회하거나 가져온 entity(도메인)를 dto로 변환 용도
    public UserResponseDto(User entity) {
        this.id = entity.getId();
        this.email = entity.getEmail();
        this.nickname = entity.getNickname();
        this.imageUrl = entity.getImageUrl();
        this.socialType = entity.getSocialType();
        this.createdTime = entity.getCreatedTime();
        this.moreInfo1 = entity.getMoreInfo1();
        this.moreInfo2 = entity.getMoreInfo2();
        this.moreInfo3 = entity.getMoreInfo3();
    }
}
