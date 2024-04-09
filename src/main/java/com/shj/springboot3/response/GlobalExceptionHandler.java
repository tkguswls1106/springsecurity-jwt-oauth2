package com.shj.springboot3.response;

import com.shj.springboot3.response.exeption.LoginIdDuplicateException;
import com.shj.springboot3.response.exeption.NoSuchUserException;
import com.shj.springboot3.response.responseitem.MessageItem;
import com.shj.springboot3.response.responseitem.StatusItem;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {  // 참고로 Filter는 DispacherServlet보다도 더 앞단에 위치하여, Filter에서 throw된 에러는 ExceptionHandler가 잡아내지 못한다.

    @ExceptionHandler(Exception.class)
    public ResponseEntity handleException(Exception ex) {
        if (ex.getMessage().equals("For input string: \"anonymousUser\"")) {
            return ResponseData.toResponseEntity(ResponseCode.anonymousUser_ERROR);
        }
        log.error(StatusItem.INTERNAL_SERVER_ERROR + " " + MessageItem.INTERNAL_SERVER_ERROR + "\n" + "==> error_messege / " + ex.getMessage());
        return ResponseData.toResponseEntity(ResponseCode.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity handleUnauthorizedException(Exception ex) {
        // log.error(StatusItem.UNAUTHORIZED + " " + MessageItem.UNAUTHORIZED + "\n" + "==> error_messege / " + ex.getMessage());
        // 401 에러는 딱히 로그의 특징성에서 의미가 없어서, 로그의 가독성을 위해 logback 출력에서 제외시키도록 하겠다.
        return ResponseData.toResponseEntity(ResponseCode.UNAUTHORIZED_ERROR);
        // 사실 이건 의미가 없는게, 예외처리권한이 JwtAuthenticationEntryPoint 에게 넘어가기에 크롬콘솔에선 설정한방식대로 출력되지않는다.
        // 하지만 이는 postman 프로그램 에서 출력받아 확인할 수 있다.
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity handleForbiddenException(Exception ex) {
        log.error(StatusItem.FORBIDDEN + " " + MessageItem.FORBIDDEN  + "\n" + "==> error_messege / " + ex.getMessage());
        return ResponseData.toResponseEntity(ResponseCode.FORBIDDEN_ERROR);
        // 사실 이건 의미가 없는게, 예외처리권한이 JwtAccessDeniedHandler 에게 넘어가기에 크롬콘솔에선 설정한방식대로 출력되지않는다.
        // 하지만 이는 postman 프로그램 에서 출력받아 확인할 수 있다.
    }

    @ExceptionHandler(LoginIdDuplicateException.class)
    public ResponseEntity handleLoginIdDuplicateException(LoginIdDuplicateException ex) {
        log.error(ex.getErrorStatus() + " " + ex.getErrorMessage() + "\n" + "==> error_data by duplicate / " + "loginId = " + ex.getLoginId());
        return ResponseData.toResponseEntity(ResponseCode.DUPLICATE_USER);
    }

    @ExceptionHandler(NoSuchUserException.class)
    public ResponseEntity handleNoSuchUserException(NoSuchUserException ex) {
        log.error(ex.getErrorStatus() + " " + ex.getErrorMessage() + "\n" + "==> error_messege / " + ex.getMessage());
        return ResponseData.toResponseEntity(ResponseCode.NOT_FOUND_USER);
    }
}