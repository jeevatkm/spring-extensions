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
package com.myjeeva.spring.security.util;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.springframework.util.AntPathMatcher;
import org.springframework.util.Assert;

/**
 * Concrete implementation of {@link SecureUriMapper} that obtains URI/URL's pass key from the application context.
 * <p>
 * So {@link #getPassKey(String)} method applies the Ant-style path patterns for verification.
 *
 * @since v1.0.1
 * @author Jeevanandam (jeeva@myjeeva.com)
 */
public class SecureUriMapperImpl implements SecureUriMapper {
	
	private Map uriMappings;
	private AntPathMatcher antPathMather = new AntPathMatcher();
	
	/**
	 * Constructor
	 */
	public SecureUriMapperImpl() {
		uriMappings = new HashMap();		
	}
		
	/**
     * Returns the respective URI/URL name mapping specified via {@link SecureUriMapperImpl#setUriMappings(Map)}
     */
	public Map getUriMappings() {
		return uriMappings;
	}

	/**
     * Set to map the pass key and Ant-style path patterns
     * In a Spring XML ApplicationContext, a definition would look something like this:
     * <pre>
     *  &lt;property name="uriMappings">
     *      &lt;map>
     *          &lt;entry key="tg54f54h59e">&lt;value>/data/secure/*&lt;/value>&lt;/entry>
     *          &lt;entry key="34ti94l2qo">&lt;value>/protected/*&lt;/value>&lt;/entry>
     *      &lt;/map>
     * &lt;/property></pre>
     *
     * @param uriMappings - A Map consisting of String keys and String values, where for each entry the key is the string
     *        representation of an password, and the value is the string representation of the corresponding Ant-style path patterns; 
     *        where filter will intercept.
     *
     * @throws IllegalArgumentException if input map does not consist of String keys and values.
     */
	public void setUriMappings(Map inputUriMappings) {
		Assert.notNull(uriMappings, "A valid list URI/URL mappings must be provided");

		uriMappings.clear();

        Iterator it = inputUriMappings.entrySet().iterator();

        while (it.hasNext()) {
        	 Map.Entry entry = (Map.Entry) it.next();
        	 uriMappings.put((String) entry.getKey(), (String) entry.getValue());
        }

        if (uriMappings.size() < 1) {
            throw new IllegalArgumentException("must map at least one URI/URL and Pass Key");
        }
	}
	
	/** 
	 * {@inheritDoc}
	 */
	public String getPassKey(String uri) {
		Iterator iter = uriMappings.keySet().iterator();

        while (iter.hasNext()) {
        	String passKey = (String) iter.next();
        	if(antPathMather.match((String)uriMappings.get(passKey), uri)) {
        		return passKey;
        	}
        }

        return null;
	}	
	
}
