package com.github.joshiste.spring.boot.admin.samples.authorization;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.HashMap;
import java.util.Map;

public class TokenJwtEnhancer implements TokenEnhancer {


	/**
	 * Enhance o auth 2 access token.
	 *
	 * @param accessToken the access token
	 * @param oAuth2Authentication the o auth 2 authentication
	 * @return the o auth 2 access token
	 */
	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken,
			OAuth2Authentication oAuth2Authentication) {
		final Map<String, Object> additionalInfo = new HashMap<>(8);
		additionalInfo.put("timestamp", System.currentTimeMillis());
		Authentication authentication = oAuth2Authentication.getUserAuthentication();
		if (authentication != null
				&& authentication.getPrincipal() instanceof UserDetails) {
			User principal = (User) authentication.getPrincipal();
			additionalInfo.put("username", principal.getUsername());
		}

		((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);

		return accessToken;
	}
}
