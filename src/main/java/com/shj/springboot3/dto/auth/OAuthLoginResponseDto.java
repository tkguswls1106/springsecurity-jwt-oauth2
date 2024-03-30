package com.shj.springboot3.dto.auth;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class OAuthLoginResponseDto {

    private Boolean isNewUser;
    private String redirectMessage;
    private TokenDto tokenDto;
}
