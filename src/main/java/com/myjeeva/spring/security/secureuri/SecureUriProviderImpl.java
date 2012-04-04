/* The MIT License
 *
 * Copyright (c) 2010-2012 www.myjeeva.com
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE. 
 * 
 */
package com.myjeeva.spring.security.secureuri;

import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.Assert;

import com.myjeeva.spring.security.util.SecureUriMapper;
import com.myjeeva.spring.security.util.SpringExtensionsUtil;

/**
 * <p>Implementation of {@link SecureUriProvider} interface Secure link computation.</p>
 * 
 * <p>So {@link #generateSecureUri(String, long, String)} method generates the secure link with given params</p>
 *
 * @since v1.0.1
 * 
 * @author Jeevanandam (jeeva@myjeeva.com)
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
	 */
	public String generateSecureUri(String file, long expiryTime, String additionalParams) {
		
		if(null == file || file.trim().isEmpty()) {
			throw new IllegalArgumentException("file URI/URL cannot be null or empty");
		}
		
		String params = "";
		if(null != additionalParams && !additionalParams.trim().isEmpty()) {
			params = additionalParams;
		}
		
		String passKey = secureUriMapper.getPassKey(file);
		// use UTC time since the server does
		long timeStamp = (expiryTime > 0) ? (new Date().getTime() + expiryTime) : expiryTime;
		
		// composing salt value and generate hash value
		String salt = passKey + file + "?e=" + Long.toString(timeStamp);		
		String hashValue = SpringExtensionsUtil.getMD5(salt);
		
		// generating secure link
		String secureUri = file + "?e=" + Long.toString(timeStamp) + "&h=" + hashValue + params;
		LOG.info("Generated Secure Link: (" + secureUri +")");
		
		return secureUri;
	}
	
}
