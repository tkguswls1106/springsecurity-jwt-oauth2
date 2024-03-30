package com.shj.springboot3.oauth;

import com.shj.springboot3.domain.user.Role;
import com.shj.springboot3.domain.user.SocialType;
import com.shj.springboot3.domain.user.User;
import com.shj.springboot3.oauth.userinfo.GoogleOAuth2UserInfo;
import com.shj.springboot3.oauth.userinfo.KakaoOAuth2UserInfo;
import com.shj.springboot3.oauth.userinfo.NaverOAuth2UserInfo;
import com.shj.springboot3.oauth.userinfo.OAuth2UserInfo;
import lombok.Builder;
import lombok.Getter;

import java.util.Map;
import java.util.UUID;

/**
 * 각 소셜에서 받아오는 데이터가 다르므로,
 * 소셜별로 데이터를 받는 데이터를 분기 처리하는 DTO 클래스
 */
@Getter
public class OAuthAttributes {

    // 아래 두 필드 모두, 이후에 CustomOAuth2UserService에서 값을 얻어 빌더로 생성 후 반환할 예정임.
    private String nameAttributeKey;  // OAuth2 로그인 진행 시 키가 되는 필드 값으로, PK와 같은 의미임.
    private OAuth2UserInfo oauth2UserInfo;  // 소셜 타입별 로그인 유저 정보(닉네임, 이메일, 프로필 사진 등등)

    @Builder
    private OAuthAttributes(String nameAttributeKey, OAuth2UserInfo oauth2UserInfo) {
        this.nameAttributeKey = nameAttributeKey;
        this.oauth2UserInfo = oauth2UserInfo;
    }

    /**
     * SocialType에 맞는 메소드 호출하여 OAuthAttributes 객체 반환
     * 파라미터 : userNameAttributeName -> OAuth2 로그인 시 키(PK)가 되는 값 / attributes : OAuth 서비스의 유저 정보들
     * 소셜별 of 메소드(ofGoogle, ofKaKao, ofNaver)들은 각각 소셜 로그인 API에서 제공하는
     * 회원의 식별값(id), attributes, nameAttributeKey를 저장 후 build
     */
    public static OAuthAttributes of(SocialType socialType,
                                     String userNameAttributeName, Map<String, Object> attributes) {

        if (socialType == SocialType.NAVER) {
            return ofNaver(userNameAttributeName, attributes);
        }
        if (socialType == SocialType.KAKAO) {
            return ofKakao(userNameAttributeName, attributes);
        }
//        if (socialType == SocialType.GOOGLE) {
//            return ofKakao(userNameAttributeName, attributes);
//        }
        return ofGoogle(userNameAttributeName, attributes);
    }

    private static OAuthAttributes ofKakao(String userNameAttributeName, Map<String, Object> attributes) {
        return OAuthAttributes.builder()
                .nameAttributeKey(userNameAttributeName)
                .oauth2UserInfo(new KakaoOAuth2UserInfo(attributes))
                .build();
    }

    public static OAuthAttributes ofGoogle(String userNameAttributeName, Map<String, Object> attributes) {
        return OAuthAttributes.builder()
                .nameAttributeKey(userNameAttributeName)
                .oauth2UserInfo(new GoogleOAuth2UserInfo(attributes))
                .build();
    }

    public static OAuthAttributes ofNaver(String userNameAttributeName, Map<String, Object> attributes) {
        return OAuthAttributes.builder()
                .nameAttributeKey(userNameAttributeName)
                .oauth2UserInfo(new NaverOAuth2UserInfo(attributes))
                .build();
    }

    /**
     * of메소드로 OAuthAttributes 객체가 생성되어, 유저 정보들이 담긴 OAuth2UserInfo가 소셜 타입별로 주입된 상태
     * OAuth2UserInfo에서 socialId(식별값), nickname, imageUrl을 가져와서 build
     * email에는 UUID로 중복 없는 랜덤 값 생성
     * role은 GUEST로 설정
     */
    public User toEntity(SocialType socialType, OAuth2UserInfo oauth2UserInfo) {
        return User.UserJoinBuilder()
                // CustomOAuth2User에서 언급한대로, email과 role도 사용하기 위해 추가하여 빌드함.
                .email(UUID.randomUUID() + "@socialUser.com")  // email은 JWT Token을 발급하기 위한 용도뿐이므로, UUID를 사용하여 임의로 설정함.
                .role(Role.ROLE_GUEST)

                .socialType(socialType)

                .socialId(oauth2UserInfo.getId())
                .nickname(oauth2UserInfo.getNickname())
                .imageUrl(oauth2UserInfo.getImageUrl())

                .build();
    }
}