package com.toeicdoit.auth.user.service;

import com.toeicdoit.auth.user.dto.JoinDto;
import com.toeicdoit.auth.user.entity.UserModel;
import com.toeicdoit.auth.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public void joinProcess(JoinDto dto){

        String username = dto.getUsername();
        String password = dto.getPassword();

        Boolean isExists = userRepository.existsByUsername(username);

        if(isExists){
            // id가 중복되서 리턴
            return;
        }
        // 회원가입 가능, 저장 진행
        UserModel data = new UserModel();

        data.setUsername(username);
        data.setPassword(passwordEncoder.encode(password));
        data.setRole("ROLE_ADMIN");

        userRepository.save(data);

    }
}
