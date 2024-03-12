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

    private final UserJpaRepository userJpaRepository;


    @Transactional
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {  // 사용자아이디 기반으로 유저 정보 생성

        return userJpaRepository.findByLoginId(username)
                .map(this::createUserDetails)  // stream map으로 find된 사용자User객체를 UserDetails 객체로 변환시킴.
                .orElseThrow(() -> new UsernameNotFoundException(username + " 을 DB에서 찾을 수 없습니다."));  // DB에서 못찾았다면
    }

    private UserDetails createUserDetails(User user) {

        // 권한 가져오기
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(user.getAuthority().toString());

        return new org.springframework.security.core.userdetails.User(
                String.valueOf(user.getId()),
                user.getFirstPw(),
                Collections.singleton(grantedAuthority)  // 싱글톤은 단 하나의 객체만 컬렉션을 만들고싶을때 사용함.
        );
    }
}