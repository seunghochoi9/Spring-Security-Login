package com.toeicdoit.auth.user.controller;

import com.toeicdoit.auth.user.dto.JoinDto;
import com.toeicdoit.auth.user.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String joinProcess(JoinDto dto) {

        joinService.joinProcess(dto);

        return "success";
    }
}
