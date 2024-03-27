package com.shj.springboot3.oauth.userinfo;

import java.util.Map;

public class GoogleOAuth2UserInfo extends OAuth2UserInfo {
    // 구글의 경우에는, 네이버,카카오와는 달리 유저 정보가 감싸져 있지 않기 때문에,
    // 바로 get으로 유저 정보 Key를 사용해서 꺼내면 된다.

    public GoogleOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return (String) attributes.get("sub");
    }

    @Override
    public String getNickname() {
        return (String) attributes.get("name");
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("picture");
    }
}

/*
- 구글의 유저 정보 Response JSON 예시 -
{
   "sub": "식별값",
   "name": "name",
   "given_name": "given_name",
   "picture": "https//lh3.googleusercontent.com/~~",
   "email": "email",
   "email_verified": true,
   "locale": "ko"
}
 */