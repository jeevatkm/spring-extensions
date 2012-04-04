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

/**
 * <code>CrossDomainMapper</code> implementations provide callers with information
 * about which HTTP cross domain name are associated with which HTTPS cross domain name on the system,
 * and vice versa.
 *
 * @author Jeevanandam (jeeva@myjeeva.com)
 */
public interface CrossDomainMapper {	

    /**
     * Locates the HTTP cross domain associated with the specified HTTPS cross domain.<P>Returns <code>null</code> if unknown.</p>
     *
     * @param httpsDomainName a {@link java.lang.String} object.
     *
     * @return the HTTP cross domain name or <code>null</code> if unknown
     */
	String lookupHttpCrossDomain(String httpsDomainName);

    /**
     * Locates the HTTPS cross domain associated with the specified HTTP cross domain.<P>Returns <code>null</code> if unknown.</p>
     *
     * @param httpDomainName a {@link java.lang.String} object.
     *
     * @return the HTTPS cross domain name or <code>null</code> if unknown
     */
	String lookupHttpsCrossDomain(String httpDomainName);
}
