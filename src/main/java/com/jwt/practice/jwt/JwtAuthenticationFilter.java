package com.jwt.practice.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwt.practice.auth.PrincipalDetails;
import com.jwt.practice.model.User;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("로그인 시도 중");

        // form data 말고 json 형식으로 진행
        ObjectMapper objectMapper = new ObjectMapper();
        User user = objectMapper.readValue(request.getInputStream(), User.class);
        System.out.println("user = " + user);

        // principalDetailsService에 loadUserByUserName() 함수가 실행됨
        // 받은 아이디, 비밀번호로 로그인 시도 토큰을 만든다.
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(user.getUserName(), user.getPassword());

        // 해당 토큰으로 로그인 시도, 정상 로그인이면 정상 authentication 생성
        // DB에 있는 username과 password가 일치한다는 것 인증 성공
        Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        // authentication 객체가 세션 영역에 저장됨. => 로그인이 되었다는 것
        PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("로그인 완료됨 = " + principal.getUser().getUserName()); // 인증 정상 진행

        //  authentication 객체 리턴 => 세션에 저장된다.
        // 리턴 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 것
        // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없지만 단지 권한 처리 때문에 session 넣는다.
        return authentication;
    }

    // attemptAuthentication 실행 후 정상 인증되면 successfulAuthentication 함수가 실행.
    // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 된다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication : 정상적으로 로그인 처리 되었다는 뜻");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject("test토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10))) // JwtProperties.EXPIRATION_TIME = 10분
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUserName())
                .sign(Algorithm.HMAC512("beomgeun"));// JwtProperties.SECRET

        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
