package com.example.security.controller;

import com.example.security.config.auth.PrincipalDetails;
import com.example.security.domain.User;
import com.example.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.time.LocalDateTime;


@Controller
@RequiredArgsConstructor
@Slf4j
public class IndexController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    /**
     * 일반 로그인 세션정보 확인
     * 로그인 후 Authentication authentication를 받으면
     * (PrincipalDetails) authentication.getPrincipal() (중요 정보라는 말) (PrincipalDetails)로 타입 캐스팅해서 사용
     * PrincipalDetails -> UserDetails 구현체이기 때문에 userDetails로도 타입 캐스팅 가능
     */
    @GetMapping("/test/login")
    public @ResponseBody String loginTest(
            Authentication authentication,
            @AuthenticationPrincipal UserDetails userDetails){ //DI 의존성주입
        PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
        log.info("authentication.getPrincipal.getUser={}", principal.getUser());

        log.info("userDetails.getUsername={}", principal.getUser());
        return "세션정보 확인";
    }

    /**
     * OAuth2.0 세션 정보 확인
     * 로그인 후 Authentication authentication를 받으면
     * (OAuth2User) authentication.getPrincipal() 와 같이 OAuth2User로 타입 캐스팅 후
     * 정보를 가져옴
     */
    @GetMapping("/test/oauth/login")
    public @ResponseBody String oAuthLoginTest(
            Authentication authentication,
            @AuthenticationPrincipal OAuth2User oAuth2User){ //DI 의존성주입
//        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        log.info("oAuth2User.getAttributes={}", oAuth2User.getAttributes());

        return "OAuth 세션정보 확인";
    }

    @GetMapping("/")
    public String home(){
        // mustache 기본폴더 src/main/resources
        // 뷰 리졸버 설정 prefix: /templates/ , suffix: .mustache
        // index.mustache
        return "index";
    }

    @GetMapping("/user")
    @ResponseBody
    public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        log.info("principalDetails.getUser()={}", principalDetails.getUser());

        return "user";
    }

    @GetMapping("/admin")
    @ResponseBody
    public String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    @ResponseBody
    public String manager() {
        return "manager";
    }

    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    /**
     * 1. userJoinForm 이라는 DTO 객체 생성
     * 2. 폼 유효성 검증필요, Validator도 필요할지도
     * 3. 유저에 인가부여 서비스 필요
     */
    @PostMapping("/join")
    public String join(User user) {
        user.setRole("ROLE_USER");
        String rawPassword = user.getPassword();
        String encodedPassword = passwordEncoder.encode(rawPassword);
        user.setPassword(encodedPassword);
        user.setCreatedDate(LocalDateTime.now());
        userRepository.save(user); // 비밀번호가 평문으로 전송, 시큐리티로 로그인이 안됨
        return "redirect:/loginForm";
    }

    @GetMapping("/info")
    @Secured("ROLE_ADMIN")
    @ResponseBody
    public String info() {
        return "개인정보";
    }

    @GetMapping("/data")
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @ResponseBody
    public String data() {
        return "데이터정보";
    }

}
