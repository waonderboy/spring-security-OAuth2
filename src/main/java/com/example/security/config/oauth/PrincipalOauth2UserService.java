package com.example.security.config.oauth;

import com.example.security.config.auth.PrincipalDetails;
import com.example.security.domain.User;
import com.example.security.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import java.util.List;
import java.util.stream.Collectors;

import static org.springframework.util.ObjectUtils.*;

@Service
@Slf4j
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

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

        String provider = userRequest.getClientRegistration().getRegistrationId(); // google
        String providerId = oAuth2User.getAttribute("sub");
        String username = provider + "_" + providerId;
        String password = bCryptPasswordEncoder.encode("getinthere");
        String email = oAuth2User.getAttribute("email");
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
        }


        // 회원가입 강제로 할 예정
        return new PrincipalDetails(user, oAuth2User.getAttributes());
    }
}
