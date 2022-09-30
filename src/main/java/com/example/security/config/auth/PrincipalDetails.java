package com.example.security.config.auth;

import com.example.security.domain.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

/**
 * 시큐리티가 /login을 낚아채 로그인을 진행
 * 로그인 진행완료가 되면 시큐리티 session을 만들어줌 (서블릿이 만들어주는 세션x)
 * Security ContextHolder 라는 키값에 세션 정보 저장
 * 시큐리티 세션에 들어갈수있는 오브젝트가 정해 Authentication 객체가 있음
 * Authentication 객체안에는 User 정보가 있어야 함
 * User 객체의 타입 = UserDetails 타입
 *
 * Security Session => Authentication => UserDetails(PrincipalDetails)
 */
public class PrincipalDetails implements UserDetails {

    private User user;

    public PrincipalDetails(User user) {
        this.user = user;
    }

    // 해당 유저의 권한을 리턴
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(() -> user.getRole()); // GrantedAuthority 인터페이스에 메서드가 하나만 있어서 익명함수대신 람다 사용 가능;
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        // 사이트에서 일년동안 로그인을 안함 -> 휴면계정
        // return false
        return true;
    }
}
