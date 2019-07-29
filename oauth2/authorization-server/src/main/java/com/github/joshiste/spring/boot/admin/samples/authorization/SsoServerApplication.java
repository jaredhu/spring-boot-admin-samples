package com.github.joshiste.spring.boot.admin.samples.authorization;

import org.apache.catalina.filters.RequestDumperFilter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.SessionAttributes;

import java.security.Principal;

@SpringBootApplication
public class SsoServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(SsoServerApplication.class, args);
    }

    /**
     * 为测试环境添加相关的 Request Dumper information，便于调试
     * @return
     */
    //@Profile("!cloud")
    //@Bean
    RequestDumperFilter requestDumperFilter() {
        return new RequestDumperFilter();
    }


    @RestController
    @SessionAttributes("authorizationRequest")
    public static class UserController {
        @RequestMapping("/user")
        public Principal user(Principal user) {
            return user;
        }
    }
}
