package com.shj.springboot3.oauth;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import java.util.Collection;
import java.util.Map;

@Getter
public class CustomOAuth2User extends DefaultOAuth2User {
    // CustomOAuth2User를 구현하는 이유는, Resource Server(카카오 이런곳)에서 제공하지 않는 추가 정보들을 내 서비스에서 가지고 있기 위함임.
    // 따라서 Resourc Server에서 제공하는 정보만 사용해도 되는 프로젝트라면, 굳이 CustomOAuth2User를 구현하지 않고, 일반 DefalutOAuth2User를 사용하면 된다.

    private String email;
    private Role role;

    /**
     * Constructs a {@code DefaultOAuth2User} using the provided parameters.
     *
     * @param authorities      the authorities granted to the user
     * @param attributes       the attributes about the user
     * @param nameAttributeKey the key used to access the user's &quot;name&quot; from
     *                         {@link #getAttributes()}
     */
    public CustomOAuth2User(Collection<? extends GrantedAuthority> authorities,
                            Map<String, Object> attributes,
                            String nameAttributeKey,
                            String email,
                            Role role) {
        // super()로 부모 객체인 DefaultOAuth2User를 생성하고,
        // email과 role 파라미터를 추가로 받아서, 주입하여 CustomOAuth2User를 생성함.

        super(authorities, attributes, nameAttributeKey);  // super()로 부모인 DefaultOAuth2User 클래스의 생성자를 호출함.
        this.email = email;
        this.role = role;
    }
}