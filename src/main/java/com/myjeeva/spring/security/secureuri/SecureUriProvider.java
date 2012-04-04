package com.myjeeva.spring.security.secureuri;

public interface SecureUriProvider {

	public abstract String generateSecureUri(String uri, long expiryTime, String additionalParams);

}