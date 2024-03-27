package com.shj.springboot3.domain.user;

import com.shj.springboot3.oauth.SocialType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);  // email로 사용자 1명 검색하기.

    // 추가정보를 아직 입력하지않은 상태(Role이 GUEST일때)일때, 아직 추가정보가 null로 빠져있기에,
    // 추가 정보를 입력받아 회원 가입을 진행할 때 '소셜 타입, 식별자'로 해당 회원을 찾기 위한 메소드임.
    Optional<User> findBySocialTypeAndSocialId(SocialType socialType, String socialId);
}
