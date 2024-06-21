package com.toeicdoit.auth.user.service;

import com.toeicdoit.auth.user.dto.CustomUserDetails;
import com.toeicdoit.auth.user.entity.UserModel;
import com.toeicdoit.auth.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Log4j2
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("UserDetailsService의 loadUserByUsername에 들어옴");
        UserModel userData = userRepository.findByUsername(username);

        if (userData != null) {
            log.info("user 찾았고, UserDetails로 넘어가는 중..");
            return new CustomUserDetails(userData);
        }
        return null;
    }
}
