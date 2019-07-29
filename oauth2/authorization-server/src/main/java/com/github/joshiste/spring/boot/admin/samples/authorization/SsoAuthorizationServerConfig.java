package com.github.joshiste.spring.boot.admin.samples.authorization;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.ArrayList;
import java.util.List;

/**
 * Created on 2017/12/26.
 *
 * @author zlf
 * @since 1.0
 */
@Configuration
@EnableAuthorizationServer
public class SsoAuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {


    @Autowired
    private AuthenticationManager authenticationManager;   //认证方式
    @Autowired
    private UserDetailsService ssoUserDetailsService;
    /**
     * 客户端一些配置
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("merryyou1")
                .secret(new BCryptPasswordEncoder().encode("merryyousecrect1"))
                .authorizedGrantTypes("authorization_code", "refresh_token")
                .redirectUris("http://localhost:8080/login")
                .scopes("all","read","write").accessTokenValiditySeconds(30)
                .autoApprove(true)
                .and()
                .withClient("merryyou2")
                .secret(new BCryptPasswordEncoder().encode("merryyousecrect2"))
                .authorizedGrantTypes("authorization_code", "refresh_token")
                .redirectUris("http://localhost:8082/login")
                .scopes("all","read","write").accessTokenValiditySeconds(30)
                .autoApprove(true)
                .and()
                .withClient("test")
                .secret(new BCryptPasswordEncoder().encode("test123456"))
                .authorizedGrantTypes("password","authorization_code", "refresh_token")
                .redirectUris("http://www.baidu.com")
                .scopes("all","read","write").accessTokenValiditySeconds(30)
                .autoApprove(true)
                .and()
                .withClient("auth")
                .secret(new BCryptPasswordEncoder().encode("authsecrect"))
                .authorizedGrantTypes("password","authorization_code", "refresh_token")
                .redirectUris("http://www.baidu.com")
                .scopes("all","read","write").accessTokenValiditySeconds(30)
                .autoApprove(true);
    }

    /**
     * 配置jwttokenStore ,注入authenticationManager 支持password模式，否则不支持
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.tokenStore(jwtTokenStore()).authenticationManager(authenticationManager).userDetailsService(ssoUserDetailsService);

            TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
            List<TokenEnhancer> enhancers = new ArrayList<>();
            enhancers.add(jwtTokenEnhancer());
            enhancers.add(jwtAccessTokenConverter());
            tokenEnhancerChain.setTokenEnhancers(enhancers);
            endpoints.tokenEnhancer(tokenEnhancerChain)
                    .accessTokenConverter(jwtAccessTokenConverter());
    }

    /**
     * springSecurity 授权表达式，访问merryyou tokenkey时需要经过认证
     * @param security
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.tokenKeyAccess("isAuthenticated()");
        /*security.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
        security.allowFormAuthenticationForClients();*/
    }

    /**
     * JWTtokenStore
     * @return
     */
    @Bean
    public TokenStore jwtTokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    /**
     * 生成JTW token
     * @return
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter(){
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey("bcrypt");
        return converter;
    }

    /**
     * jwt 生成token 定制化处理
     *
     * @return TokenEnhancer
     */
    @Bean
    @ConditionalOnBean(TokenEnhancer.class)
    public TokenEnhancer jwtTokenEnhancer() {
        return new TokenJwtEnhancer();
    }
}
