package com.example.security.config.oauth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
    // 구글로 받은 userRequest 데이터를 후처리
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("userRequest.getClientRegistration={}", userRequest.getClientRegistration());
        log.info("userRequest.getAccessToken={}", userRequest.getAccessToken().getTokenValue());
        // 구글 로그인 버튼 -> 구글 로그인 창
        log.info("userRequest.getAttributes={}", super.loadUser(userRequest));

        // 회원가입 강제로 진행
        OAuth2User oAuth2User = super.loadUser(userRequest);

        return super.loadUser(userRequest);
    }
}
