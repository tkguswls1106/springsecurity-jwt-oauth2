package com.shj.springboot3.response.responseitem;

public class MessageItem {
    public static final String LOGIN_SUCCESS = "SUCCESS - 로그인 성공";
    public static final String UPDATE_PASSWORD = "SUCCESS - 비밀번호 수정 성공";
    public static final String LOGIN_FAIL = "SUCCESS - 로그인 실패";

    public static final String UNAUTHORIZED = "ERROR - Unauthorized 에러";
    public static final String FORBIDDEN = "ERROR - Forbidden 에러";

    public static final String REISSUE_SUCCESS = "SUCCESS - JWT Access 토큰 재발급 성공";
    public static final String TOKEN_EXPIRED = "ERROR - JWT 토큰 만료 에러";

    public static final String CREATED_USER = "SUCCESS - 회원 가입 성공";
    public static final String READ_USER = "SUCCESS - 회원 정보 조회 성공";
    public static final String UPDATE_USER = "SUCCESS - 회원 정보 수정 성공";
    public static final String DELETE_USER = "SUCCESS - 회원 탈퇴 성공";
    public static final String NOT_FOUND_USER = "ERROR - 회원을 찾을 수 없습니다.";
    public static final String DUPLICATE_USER = "ERROR - 회원가입 로그인아이디 중복 에러";

    public static final String READ_IS_LOGIN = "SUCCESS - 현재 로그인 여부 조회 성공";
    public static final String anonymousUser_ERROR = "ERROR - anonymousUser 에러";

    public static final String INTERNAL_SERVER_ERROR = "ERROR - 서버 내부 에러";

    public static final String HEALTHY_SUCCESS = "SUCCESS - Health check 성공";

    public static final String GET_LOGIN = "204 - login api를 get method로 호출하였음";
}
