package com.toeicdoit.auth.user.dto;

import com.toeicdoit.auth.user.entity.UserModel;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Log4j2
@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails {

    private final UserModel user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Collection<GrantedAuthority> collection = new ArrayList<>();

        collection.add(new SimpleGrantedAuthority(user.getRole()));
        log.info("SimpleGrantedAuthority 했을 경우 : "+new SimpleGrantedAuthority(user.getRole()));

        // 둘다 같은 값 나옴
//        collection.add(new GrantedAuthority() {
//            @Override
//            public String getAuthority() {
//                log.info(user.getRole());
//                return user.getRole();
//            }
//        });

        return collection;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }
}
