package com.shj.springboot3.domain.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserJpaRepository extends JpaRepository<User, Long> {

    Optional<User> findByLoginId(String loginId);  // 로그인아이디로 사용자 1명 검색하기.
}
