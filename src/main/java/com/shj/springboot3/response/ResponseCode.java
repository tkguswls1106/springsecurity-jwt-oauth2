package com.shj.springboot3.response;

import com.shj.springboot3.response.responseitem.MessageItem;
import com.shj.springboot3.response.responseitem.StatusItem;
import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum ResponseCode {

    CREATED_USER(StatusItem.CREATED, MessageItem.CREATED_USER),
    NOT_FOUND_USER(StatusItem.NOT_FOUND, MessageItem.NOT_FOUND_USER),
    DUPLICATE_USER(StatusItem.BAD_REQUEST, MessageItem.DUPLICATE_USER),

    // 기타 성공 응답
    READ_IS_LOGIN(StatusItem.OK, MessageItem.READ_IS_LOGIN),
    LOGIN_SUCCESS(StatusItem.OK, MessageItem.LOGIN_SUCCESS),
    GET_LOGIN(StatusItem.NO_CONTENT, MessageItem.GET_LOGIN),
    UPDATE_PASSWORD(StatusItem.NO_CONTENT, MessageItem.UPDATE_PASSWORD),
    HEALTHY_SUCCESS(StatusItem.OK, MessageItem.HEALTHY_SUCCESS),

    // 기타 실패 응답
    INTERNAL_SERVER_ERROR(StatusItem.INTERNAL_SERVER_ERROR, MessageItem.INTERNAL_SERVER_ERROR),
    anonymousUser_ERROR(StatusItem.INTERNAL_SERVER_ERROR, MessageItem.anonymousUser_ERROR),
    UNAUTHORIZED_ERROR(StatusItem.UNAUTHORIZED, MessageItem.UNAUTHORIZED),
    FORBIDDEN_ERROR(StatusItem.FORBIDDEN, MessageItem.FORBIDDEN),

    // ===================== //
    ;

    private int httpStatus;
    private String message;
}