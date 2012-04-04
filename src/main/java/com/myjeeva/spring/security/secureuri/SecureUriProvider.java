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

/**
 * <p>Concrete implementation of {@link SecureUriProvider} that holds definitions of Secure link computation.</p>
 * <p>Like Content link restriction, link restriction, timed link validity, download link protection, etc.</p> 
 * 
 * <p>So {@link #generateSecureUri(String, long, String)} method generates the secure link with given params</p>
 *
 * @since v1.0.1
 * 
 * @author Jeevanandam (jeeva@myjeeva.com)
 */
public interface SecureUriProvider {

	/**
	 * Generate a secure link/download link for the given parameters. This function will return a hashed URL.
	 * 
	 * <p>for compute a secure URI below params are used.</p>
	 * @param file - <code>String</code> - base URI, i.e everything after myjeeva.com in file path, including the leading slash 
	 * <br/>(for example: http://myjeeva.com/view/content/file.txt<br/>http://myjeeva.com/view/content/index.jsp
	 * <br/>http://myjeeva.com/content/sample.pdf)
	 * @param expiryTime - <code>long</code> - expiry in milliseconds since current time. Use 0 for no expiry
	 * @param additionalParams - <code>String</code> - custom URL parameters (query String)
	 * @return secure link of hash URL - a {@link java.lang.String} object
	 */
	public abstract String generateSecureUri(String file, long expiryTime, String additionalParams);

}