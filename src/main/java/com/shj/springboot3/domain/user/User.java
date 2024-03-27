package com.shj.springboot3.domain.user;

import com.shj.springboot3.oauth.Role;
import com.shj.springboot3.oauth.SocialType;
import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Getter
@NoArgsConstructor

@Table(name = "user")
@Entity
public class User implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    @Column(name = "email", unique = true)
    private String email;

    private String socialId;
    private String nickname;
    private String imageUrl;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Enumerated(EnumType.STRING)
    private SocialType socialType;  // KAKAO, NAVER, GOOGLE

    private String moreInfo;


    @Builder
    public User(Long id, String email, String nickname) {
        this.id = id;
        this.email = email;
        this.nickname = nickname;
    }

    @Builder(builderClassName = "UserJoinBuilder", builderMethodName = "UserJoinBuilder")
    public User(String email, Role role, SocialType socialType, String socialId, String nickname, String imageUrl) {
        // 이 빌더는 사용자 회원가입때만 사용할 용도
        this.email = email;
        this.role = role;

        this.socialType = socialType;

        this.socialId = socialId;
        this.nickname = nickname;
        this.imageUrl = imageUrl;

        // moreInfo는 null로 들어간다.
    }


    public void updateRole() {  // 추가정보 입력후, Role을 GUEST->USER로 업데이트.
        this.role = Role.USER;
    }
    public void updateMoreInfo(String moreInfo) {
        this.moreInfo = moreInfo;
    }
}