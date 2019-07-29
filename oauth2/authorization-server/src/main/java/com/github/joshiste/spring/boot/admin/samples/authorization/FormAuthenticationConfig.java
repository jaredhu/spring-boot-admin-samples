package com.github.joshiste.spring.boot.admin.samples.authorization;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;


/**
 * 表单登录配置
 * @author jared
 */
@Component(value = "formAuthenticationConfig")
public class FormAuthenticationConfig {

    @Autowired
    private AuthenticationSuccessHandler authAuthenticationSuccessHandler;

	/**
	 * 表单登录配置.
	 *
	 * @param http the http
	 *
	 * @throws Exception the exception
	 */
	void configure(HttpSecurity http) throws Exception {
/*		http.formLogin().loginPage("/login").permitAll().successHandler(authAuthenticationSuccessHandler).and().requestMatchers()
				.antMatchers("/uaa/actuator/health").and().requestMatchers()
				.antMatchers("/login","/oauth/authorize", "/oauth/confirm_access","/favicon.ico").and()
				.authorizeRequests().anyRequest().authenticated()
				.and().csrf().ignoringAntMatchers("/oauth/**");*/
/*
		http.formLogin().loginPage("/login").permitAll().and().requestMatchers()
				.antMatchers("/login", "/oauth/authorize", "/oauth/confirm_access").and()
				.authorizeRequests().anyRequest().authenticated().and().requestMatchers()
				.antMatchers("/actuator/health").and().authorizeRequests().anyRequest().permitAll()
				.and().csrf().ignoringAntMatchers("/oauth/**", "/actuator/**");
*/

		http.formLogin().loginPage("/login").permitAll().successHandler(authAuthenticationSuccessHandler)
				.and().requestMatchers().antMatchers("/actuator/**","/login", "/oauth/authorize", "/oauth/confirm_access").and()
				.authorizeRequests().anyRequest().authenticated().and().requestMatchers()
				.antMatchers("/actuator/health").and().authorizeRequests().anyRequest().permitAll()
				//.and().authorizeRequests().anyRequest().authenticated()
				.and().csrf().ignoringAntMatchers("/oauth/**", "/actuator/**");
	}

}
