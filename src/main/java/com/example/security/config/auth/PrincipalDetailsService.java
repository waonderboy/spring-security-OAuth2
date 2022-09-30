package com.example.security.config.auth;

import com.example.security.domain.User;
import com.example.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Security Session => Authentication => UserDetails(PrincipalDetails)
 * Authentication
 * Security Config 중 loginProcessUrl("/login") 으로 요청이 오면
 * 자동으로 UserDetailsService로 IoC 되어있는 loadUserByUsername 함수가 호출
 */

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    // 시큐리티 session(내부 Authentication(내부 UserDetails))
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User findUser = userRepository.findByUsername(username);
        if (findUser != null) {
            return new PrincipalDetails(findUser);
        }

        return null;
    }
}
