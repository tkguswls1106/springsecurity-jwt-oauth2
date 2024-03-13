package com.shj.springboot3.service.auth;

import com.shj.springboot3.domain.user.User;
import com.shj.springboot3.domain.user.UserJpaRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    // AuthenticationManager는 필터로부터 인증 처리를 위임받는 클래스로서 내부적으로 AuthenticationProvider를 가지고 있고,
    // AuthenticationProvider는 DB에서 가져온 정보와 input된 정보가 비교되서 체크되는 로직이 포함되어있는 인터페이스로써, UserDetailsService를 사용해서 사용자의 정보를 참조하는 식으로 관계를 맺고 있다.
    // 이 때 직접 UserDetailsService 인터페이스를 상속받는 CustomDetailsService를 등록하게 되면,
    // AuthenticationManager 인증 절차시, 시큐리티가 자동으로 사용자가 등록해둔 CustomDetailsSerivce를 우선적으로 사용해서 인증처리를 하도록 매커니즘이 구성되어있음.
    // 비밀번호 일치 체킹 과정은 createUserDetails 메소드에서 'new org.springframework.security.core.userdetails.User'객체를 생성할때 일어난다.
    // 이 과정에서 SecurityConfig에서 등록했던 PasswordEncoder Bean 객체를 통해 Spring Security 내부적으로 이루어진다. 따라서 조회된 User에는 패스워드가 해당 PasswordEncoder를 통해 암호화된 상태로 저장되어 있어야한다.
    private final UserJpaRepository userJpaRepository;


    @Transactional
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 이 파라미터의 username은 'UserLoginRequestDto에서 변환된 UsernamePasswordAuthenticationToken 객체'에 저장해둔 로그인계정아이디를 의미하며, 이를 비교하는 역할이다.

        return userJpaRepository.findByLoginId(username)
                .map(this::createUserDetails)  // stream map으로 find된 사용자User객체를 UserDetails 객체로 변환시킴.
                .orElseThrow(() -> new UsernameNotFoundException(username + " 을 DB에서 찾을 수 없습니다."));  // DB에서 못찾았다면
    }

    private UserDetails createUserDetails(User user) {  // 로그인아이디를 이용하여 User을 찾고, 찾은 User의 '사용자DB의PKid,비밀번호,권한'을 가지고 UserDetails 객체를 생성한다.

        // 권한 가져오기
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(user.getAuthority().toString());

        return new org.springframework.security.core.userdetails.User(
                String.valueOf(user.getId()),  // 헷갈리지말자. 여기서 로그인아이디 대신 사용자DB의PKid를 String자료형으로 변환하여 집어넣는다.
                user.getFirstPw(),
                Collections.singleton(grantedAuthority)  // 싱글톤은 단 하나의 객체만 컬렉션을 만들고싶을때 사용함.
        );
    }
}