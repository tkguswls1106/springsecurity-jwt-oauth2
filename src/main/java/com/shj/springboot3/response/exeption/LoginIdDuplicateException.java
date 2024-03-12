package com.shj.springboot3.response.exeption;

import com.shj.springboot3.response.responseitem.MessageItem;
import com.shj.springboot3.response.responseitem.StatusItem;
import lombok.Getter;

@Getter
public class LoginIdDuplicateException extends RuntimeException {

    private Integer errorStatus;
    private String errorMessage;

    private String loginId;

    public LoginIdDuplicateException(String loginId) {
        this.errorStatus = StatusItem.BAD_REQUEST;
        this.errorMessage = MessageItem.DUPLICATE_USER;

        this.loginId = loginId;
    }
}
