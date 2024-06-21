package com.toeicdoit.auth;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootTest
class ApplicationTests {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void testEncode() {

        String password = "11111";
        String encodedPassword = passwordEncoder.encode(password);
        System.out.println("encodedPassword: "+encodedPassword);
        boolean matches = passwordEncoder.matches(password, encodedPassword);
        System.out.println("matches: "+matches);

    }

}
