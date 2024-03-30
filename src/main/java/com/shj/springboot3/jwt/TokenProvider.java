package com.shj.springboot3.jwt;

import com.shj.springboot3.domain.user.Role;
import com.shj.springboot3.dto.auth.TokenDto;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
@Component
public class TokenProvider {  // JWT를 생성하고 검증하는 역할을 하는 클래스

    private static final String AUTHORITIES_KEY = "auth";
    private static final String BEARER_TYPE = "bearer";
    private static final long ACCESS_TOKEN_EXPIRE_TIME = 1000 * 60 * 120;  // 120분 = 2시간
    private static final long REFRESH_TOKEN_EXPIRE_TIME = 1000 * 60 * 1440 * 14;  // 1440분 x 14 = 24시간 x 14 = 14일 = 2주
    private final Key key;  // 이 key는 JWT의 토큰 서명(signature)을 생성하고 검증하는 데 사용됨.


    // 주의할점은, 여기의 @Value는 'springframework.beans.factory.annotation.Value'소속이다! lombok의 @Value와 착각하지 말자!
    public TokenProvider(@Value("${jwt.secret}") String secretKey) {  // 이 생성자는 JWT의 시크릿 key를 설정하고, 이를 바탕으로 JWT를 생성하고 검증할 수 있는 TokenProvider 클래스를 초기화하는 역할임.
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }


    // 전체 토큰 새로 생성
    public TokenDto generateTokenDto(Long userId, Role role) {  // 파라미터로 전달해주는 authentication은 현재 인증 성공한 사용자를 나타내는 Authentication 객체이다.
        // (참고로 이 메소드의 파라미터 인증객체의 name 안에는 로그인계정아이디가 아닌, CustomUserDetailsService의 createUserDetails메소드에서 진행하여 나온 String으로 변환된 사용자DB의PKid가 들어있다.)

        // 사용자의 권한(authority) 정보를 문자열로 변환하는 부분임.
        // 예를 들어, 사용자가 "ROLE_USER"와 "ROLE_ADMIN" 두 가지 권한을 가지고 있다면, 위 코드는 "ROLE_USER,ROLE_ADMIN"과 같은 문자열을 생성함.
//        String authorities = authentication.getAuthorities().stream()
//                .map(GrantedAuthority::getAuthority)
//                .collect(Collectors.joining(","));
        // 어차피 권한을 하나씩밖에 안넣을것이므로, 위의 것 말고 더욱 간단하게 Role로 구성하여 코드를 바꿨음.

        String accessToken = generateAccessToken(userId, role);
        String refreshToken = generateRefreshToken();

        return TokenDto.builder()
                .grantType(BEARER_TYPE)
                .accessToken(accessToken)
                .accessTokenExpiresIn(parseClaims(accessToken).getExpiration().getTime())
                .refreshToken(refreshToken)
                .build();
    }

    // Access 토큰이 만료된 경우, Refresh Token으로 Access Token 재발급하기 (또는 signup으로 인해 헤더의 jwt 토큰에 등록해둔 권한도 수정해야할때 활용할 것임.)
    public TokenDto generateAccessTokenByRefreshToken(Long userId, Role role, String refreshToken) {
        String accessToken = generateAccessToken(userId, role);

        return TokenDto.builder()
                .grantType(BEARER_TYPE)
                .accessToken(accessToken)
                .accessTokenExpiresIn(parseClaims(accessToken).getExpiration().getTime())
                .refreshToken(refreshToken)
                .build();
    }

    // Access Token 생성 후 반환하는 메소드
    public String generateAccessToken(Long userId, Role role) {
        long now = (new Date()).getTime();
        Date accessTokenExpiresIn = new Date(now + ACCESS_TOKEN_EXPIRE_TIME);

        String strUserId = String.valueOf(userId);

        // Access Token 생성
        String accessToken = Jwts.builder()
                .setSubject(strUserId)  // Payload에 String으로 변환해둔 사용자DB의PKid와 권한 정보가 저장되어야만한다. (아이디)
                .claim(AUTHORITIES_KEY, role.name())  // Access Token은 Refresh Token과는 다르게, Payload에 사용자의 아이디와 권한 정보가 저장되어야만한다. (권한)
                .setExpiration(accessTokenExpiresIn)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();  // 컴팩트화로써, 최종적으로 JWT를 문자열로 변환하는 역할임.

        return accessToken;
    }

    // Refresh Token 생성 후 반환하는 메소드
    public String generateRefreshToken() {
        long now = (new Date()).getTime();
        Date refreshTokenExpiresIn = new Date(now + REFRESH_TOKEN_EXPIRE_TIME);

        // Refresh Token 생성
        String refreshToken = Jwts.builder()  // Refresh Token은 Access Token과는 다르게, 오직 재발급(로그인 유지)를 위한 것이므로 중요정보 Claim 없이 만료 시간만 담아줘도 된다.
                .setExpiration(refreshTokenExpiresIn)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();  // 컴팩트화로써, 최종적으로 JWT를 문자열로 변환하는 역할임.

        return refreshToken;
    }

    public Authentication getAuthentication(String accessToken) {  // Access Token의 Payload에 저장된 사용자의 아이디와 권한 정보를 토대로 인증하여 Authentication 객체를 만들어 반환하는 메소드
        Claims claims = parseClaims(accessToken);  // Access Token의 Payload에 저장된 Claim을 꺼내옴. (JWT 토큰에서 사용자의 아이디와 권한 정보를 획득할 목적)

        if (claims.get(AUTHORITIES_KEY) == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");  // 클라이언트가 잘못된 요청을 한 것이 아니라, 서버에서 처리 중에 예기치 않은 에러가 발생한 것이기에, 500 error status code가 적절하다.
        }

        // 해당 계정이 갖고있는 권한 목록들을 리턴하는 역할임.
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))  // "ROLE_USER,ROLE_ADMIN"과 같은 문자열을 ','기준으로 분리함.
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        // 위 정보를 사용하여 Spring Security의 UserDetails 사용자 정보 객체를 생성함. claims.getSubject()는 사용자의 식별자인 계정아이디를 의미함.
        // 이때, 빈 문자열 ""은 패스워드를 나타내며, 여기서는 사용되지 않는다. 왜냐하면 일반적으로 패스워드는 토큰 자체에 저장되어 있지 않기 때문이다. 대신에 토큰의 서명을 통해 검증될 것이다.
        UserDetails principal = new User(claims.getSubject(), "", authorities);  // domain의 User가 아닌, security.core.userdetails.User 이다.
        // 인증 객체 생성.
        // 이는 AuthenticationProvider를 사용하지 않은채로 UsernamePasswordAuthenticationToken 클래스로 Authentication 인증 객체를 생성하는 과정으로 이루어졌으므로,
        // 별도의 아이디+비밀번호 일치 체킹 로직 없이, 단지 제공된 자격 증명이 시스템DB에 저장된 사용자에 대한 자격 증명과 일치하는지 확인하는 인증 객체 생성 용도로 사용된 것이다. (당연히 상식적으로도 현재 로그인 유지된 사용자를 판단하는데 비밀번호를 체킹할리가 없음)
        // 즉, 쉽게말하자면 현재 로그인 되어있는 사용자의 JWT토큰에 대해 검사하여, 이를 통해 JWT토큰에서 추출한 계정아이디에 대한 사용자 정보가 시스템DB에 일치하는지 확인하고 권한 또한 확인함.
        Authentication authentication = new UsernamePasswordAuthenticationToken(principal, "", authorities);

        return authentication;  // 이 인증된 객체는 Spring Security에서 사용자의 보안 컨텍스트를 관리하고 액세스 제어 검사를 수행하는 데 사용될 수 있다.
    }

    public boolean validateToken(String token) {  // 토큰의 key서명이 일치하고 유효한지 검사하는 메소드이다. (JWT를 검증하고 처리하는 단계)
        try {
            // setSigningKey(key)는 JWT의 서명을 확인하는 데 사용되는 key를 설정하는 역할임.
            // parseClaimsJws(auth)은 JWT 문자열(auth)을 구문 분석하고 확인하는 메소드로써,
            // 토큰의 서명이 유효한 경우, 토큰에서 구문 분석된 클레임을 포함하는 'Jwts'(클레임이 포함된 JSON 웹 서명) 개체를 반환하고,
            // 서명이 유효하지 않거나 토큰 형식이 잘못된 경우, JwtException 예외 처리가 발생함.
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {  // 참고로 ExpiredJwtException은 throw 할 때 파라미터가 필요하기에, JwtExpiredException을 새로 만들어서 throw를 대신 구현하는것도 좋다.
            log.info("만료된 JWT 토큰입니다.");
            throw new JwtException("토큰 만료 - ExpiredJwtException");
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }

    private Claims parseClaims(String accessToken) {  // Access Token의 Payload에 저장된 Claim을 꺼내오는 메소드 (JWT 토큰에서 사용자의 아이디와 권한 정보를 획득할 목적)
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }
}

/*
- Access Token 만료시, 이를 Refresh Token으로 재발급 받는 과정 -
1. 프론트에서 로그인하면, 백엔드에서 Access 토큰과 Refresh 토큰을 발급해서 프론트에 전달한다. Refresh 토큰은 DB에도 저장해둔다.
2. 프론트에서는 백엔드에 api 요청을 보낼 때마다 헤더에 Access 토큰을 담아서 보낸다.
3. Access 토큰이 만료되었다는 에러응답을 백엔드로부터 받았다면, 기존의 Access 토큰과 Refresh 토큰을 dto에 담아 백엔드에게 보내서 토큰 재발급을 요청한다. (이때 헤더에 토큰은 필요없다.)
4. 전달받은 Refresh 토큰의 유효성을 검사한다.
5. 전달받은 Access 토큰에서 userId를 꺼내서 DB에 사용자를 검색하고, 해당 사용자의 Refresh 토큰이 전달받은 Refresh 토큰과 일치함을 검사한다.
6-1. 만약 위의 두 검사가 모두 통과된다면, Access 토큰을 재발급 해준다.
6-2. 만약 위의 두 검사 중에서 하나라도 통과되지 못한다면, 재발급이 안되고 재로그인을 해야한다.
 */