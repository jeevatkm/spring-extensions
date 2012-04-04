
package com.myjeeva.spring.security.secureuri;

import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.Assert;

import com.myjeeva.spring.security.util.SecureUriMapper;
import com.myjeeva.spring.security.util.SpringExtensionsUtil;

/**
 * @author jeeva
 *
 */
public class SecureUriProviderImpl implements SecureUriProvider {
	/** Logger */
	private static transient final Log LOG = LogFactory.getLog(SecureUriProviderImpl.class);
	private SecureUriMapper secureUriMapper;
		
	/**
	 * @param secureUriMapper the secureUriMapper to set
	 */
	public void setSecureUriMapper(SecureUriMapper secureUriMapper) {
		Assert.notNull(secureUriMapper, "secureUriMapper cannot be null");
		this.secureUriMapper = secureUriMapper;
	}

	/**
	 * {@inheritDoc}
	 * @see com.myjeeva.spring.security.secureuri.SecureUriProvider#generateSecureUri(java.lang.String, long, java.lang.String)
	 */
	public String generateSecureUri(String uri, long expiryTime, String additionalParams) {
		
		if(null == uri || uri.trim().isEmpty()) {
			throw new IllegalArgumentException("URI/URL cannot be null or empty");
		}
		
		String params = "";
		if(null != additionalParams && !additionalParams.trim().isEmpty()) {
			params = additionalParams;
		}
		
		String passKey = secureUriMapper.getPassKey(uri);
		// use UTC time since the server does
		long timeStamp = (expiryTime > 0) ? (new Date().getTime() + expiryTime) : expiryTime;
		
		// composing salt value and generate hash value
		String salt = passKey + uri + "?e=" + Long.toString(timeStamp);		
		String hashValue = SpringExtensionsUtil.getMD5(salt);
		
		// generating secure link
		String secureUri = uri + "?e=" + Long.toString(timeStamp) + "&h=" + hashValue + params;
		LOG.info("Generated Secure Link: (" + secureUri +")");
		
		return secureUri;
	}
	
}
