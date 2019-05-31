package com.app.security.rest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class SpringBootDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringBootDemoApplication.class, args);
    }

    @GetMapping(value = "/")
    public String homePage() {
        return "Hi, Welcome to mysite";
    }

    @GetMapping(value = "/admin")
    public String forAdmin() {
        return "Hi Admin, Welcome to mysite";
    }

    @GetMapping(value = "/user")
    public String forUser() {
        return "Hi User, Welcome to mysite";
    }

    @GetMapping(value = "/dba")
    public String forDBA() {
        return "Hi DBA, Welcome to mysite";
    }
}
