package com.example.security.config.oauth;

import com.example.security.config.auth.PrincipalDetails;
import com.example.security.config.oauth.provider.FacebookUserInfo;
import com.example.security.config.oauth.provider.GoogleUserInfo;
import com.example.security.config.oauth.provider.OAuth2UserInfo;
import com.example.security.domain.User;
import com.example.security.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import static org.springframework.util.ObjectUtils.*;

@Service
@Slf4j
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
    private static final String PROVIDER_GOOGLE = "google";
    private static final String PROVIDER_FACEBOOK = "facebook";

    @Autowired
    private UserRepository userRepository;


    // 구글로 받은 userRequest 데이터를 후처리
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("userRequest.getClientRegistration={}", userRequest.getClientRegistration());
        log.info("userRequest.getAccessToken={}", userRequest.getAccessToken().getTokenValue());
        // 회원가입 강제로 진행
        OAuth2User oAuth2User = super.loadUser(userRequest);

        // 구글 로그인 버튼 -> 구글 로그인 창
        log.info("userRequest.getAttributes={}", oAuth2User.getAttributes());

        String providerName = userRequest.getClientRegistration().getRegistrationId();
        OAuth2UserInfo oAuth2UserInfo = null;
        if (providerName.equals(PROVIDER_GOOGLE)) {
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if(providerName.equals(PROVIDER_FACEBOOK)) {
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        } else {
            throw new IllegalArgumentException("지원하지않는 Provider 입니다.");
        }

        String provider = oAuth2UserInfo.getProvider(); // google
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String password = bCryptPasswordEncoder.encode("getinthere");
        String email = oAuth2UserInfo.getEmail();
        String role = oAuth2User.getAuthorities().stream().findFirst().get().getAuthority();

        User user = userRepository.findByUsername(username);
        if (isEmpty(user)) {
            user = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(user);
        } else {
            throw new RuntimeException("이미 가입된 사용자");
        }


        // 회원가입 강제로 할 예정
        return new PrincipalDetails(user, oAuth2User.getAttributes());
    }
    
}
