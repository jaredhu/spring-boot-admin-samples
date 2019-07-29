package com.github.joshiste.spring.boot.admin.samples.authorization;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Configuration
@EnableResourceServer
public class WebMvcConfig implements WebMvcConfigurer {

//	@Override
//	public void addInterceptors(InterceptorRegistry registry) {
//		registry.addInterceptor(new LoginRequiredInterceptor()).addPathPatterns("/**")
//				.excludePathPatterns("/css/**", "/js/**", "/images/**", "/webjars/**",
//						"/**/favicon.ico", "/error");
//	}

	@Override
	public void addViewControllers(ViewControllerRegistry registry) {
		registry.addViewController("/login").setViewName("login");
		registry.addViewController("/oauth/confirm_access").setViewName("authorize");
	}


	private class LoginRequiredInterceptor  extends HandlerInterceptorAdapter {
		private final Logger logger = LoggerFactory.getLogger(LoginRequiredInterceptor.class);

		@Override
		public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
				throws Exception {
			logger.info(request.getRequestURI());
			return super.preHandle(request, response, handler);
		}

		@Override
		public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex)
				throws Exception {
			logger.info(request.getRequestURI());
			super.afterCompletion(request, response, handler, ex);
		}
	}

}
