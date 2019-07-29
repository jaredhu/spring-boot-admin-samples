package com.github.joshiste.spring.boot.admin.samples.resource;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Configuration
@EnableAutoConfiguration
@EnableResourceServer
@RestController
public class ResourceApplication extends ResourceServerConfigurerAdapter {

    public static void main(String[] args) {
        SpringApplication.run(ResourceApplication.class, args);
    }

    @RequestMapping("/")
    public String hello() {
        return "hello";
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
     /*   http.requestMatchers().requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                .requestMatchers().antMatchers("/actuator/**")
                .and().authorizeRequests().antMatchers("/actuator/**").permitAll().anyRequest()
                .authenticated();*/

        http.requestMatchers().requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                .and().authorizeRequests().antMatchers("/actuator/health","/favicon.ico").permitAll()
                .and().authorizeRequests().anyRequest().authenticated();
    }

}
