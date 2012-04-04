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
package com.myjeeva.spring.security.securechannel;


/**
 * Commences a secure channel by retrying the original request using HTTPS with mapped Cross domain name.
 * <p>
 * This entry point should suffice in most circumstances. However, it is not intended to properly handle HTTP POSTs
 * or other usage where a standard redirect would cause an issue.</p>
 *
 * @author Jeevanandam (jeeva@myjeeva.com)
 */
public class CrossDomainRetryWithHttpsEntryPoint extends AbstractCrossDomainRetryEntryPoint {
	protected static final String httpsScheme = "https://";
	protected static final int httpsPort = 443;
	
	/**
	 * Constructor
	 */
	public CrossDomainRetryWithHttpsEntryPoint() {
        super(httpsScheme, httpsPort);
    }

	/**
	 * {@inheritDoc}
	 */
    protected Integer getMappedPort(Integer mapFromPort) {
        return getPortMapper().lookupHttpsPort(mapFromPort);
    }
    
    /**
     * {@inheritDoc}
     */
    protected String getMappedDomain(String mapFromDomainName) {
    	return getCrossDomainMapper().lookupHttpsCrossDomain(mapFromDomainName);
    }
}
