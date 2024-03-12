package com.shj.springboot3.domain.user;

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

    @Column(name = "login_id", unique = true)
    private String loginId;

    @Column(name = "first_password")
    private String firstPw;

    @Column(name = "username")
    private String username;

    @Enumerated(EnumType.STRING)
    private Authority authority;


    @Builder
    public User(Long id, String loginId, String username) {
        this.id = id;
        this.loginId = loginId;
        this.username = username;
    }

    @Builder(builderClassName = "UserJoinBuilder", builderMethodName = "UserJoinBuilder")
    public User(String loginId, String firstPw, String username, Authority authority) {
        // 이 빌더는 사용자 회원가입때만 사용할 용도
        this.loginId = loginId;
        this.firstPw = firstPw;
        this.username = username;
        this.authority = authority;
    }

    @Builder(builderClassName = "UserUpdatePwBuilder", builderMethodName = "UserUpdatePwBuilder")
    public User(String loginId, String newFirstPw) {
        // 이 빌더는 사용자 1차비밀번호 수정때만 사용할 용도
        this.loginId = loginId;
        this.firstPw = newFirstPw;
    }

    @Builder(builderClassName = "UserUpdateNameBuilder", builderMethodName = "UserUpdateNameBuilder")
    public User(String username) {
        // 이 빌더는 사용자 이름 수정때만 사용할 용도
        this.username = username;
    }


    // 수정(업데이트) 기능
    public void updateFirstPw(String newFirstPw) {  // 1차 패스워드 변경 기능
        this.firstPw = newFirstPw;
    }
    public void updateUsername(String username) {  // 사용자이름 변경 기능
        this.username = username;
    }
}