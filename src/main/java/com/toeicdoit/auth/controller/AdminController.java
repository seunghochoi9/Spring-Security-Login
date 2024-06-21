package com.toeicdoit.auth.controller;


import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@Log4j2
@ResponseBody
public class AdminController {

    @GetMapping("/admin")
    public String adminP() {
        return "admin Controller";
    }

}
