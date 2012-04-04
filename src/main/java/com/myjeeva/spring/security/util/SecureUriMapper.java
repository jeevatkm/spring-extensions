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
 * <code>SecureUriMapper</code> implementations provide callers with information
 * about which URI/URL Ant-style path patterns should be secured. Examples are provided below.
 * 
 * <p>Part of this mapping code has been kindly borrowed from <a href="http://ant.apache.org/">Apache Ant</a>.</p>
 * 
 * <p>The mapping matches URLs using the following rules:</p>
 * <ul>
 *    <li>? matches one character</li>
 *    <li>* matches zero or more characters</li>
 *    <li>** matches zero or more 'directories' in a path</li>
 * </ul>
 * 
 * Some examples has been kindly borrowed from <a href="static.springsource.org/spring/docs">springsource docs</a>:
 * <ul>
 *    <li>com/t?st.jsp - matches com/test.jsp but also com/tast.jsp or com/txst.jsp</li>
 *    <li>com/*.jsp - matches all .jsp files in the com directory</li>
 *    <li>com/springframework/&#42&#42/*.jsp - matches all .jsp files underneath the org/springframework path</li>
 *    <li>org/&#42&#42/servlet/bla.jsp - matches org/springframework/servlet/bla.jsp but also org/springframework/testing/servlet/bla.jsp and org/servlet/bla.jsp</li>
 * </ul>
 * 
 * @since v1.0.1
 * 
 * @author Jeevanandam (jeeva@myjeeva.com)
 * 
 */
public interface SecureUriMapper {
	
	/**
	 * getting a pass key for given URI/URL
	 * 
	 * @param uri a {@link java.lang.String} object.
	 * @return pass key if success or <code>null</code> if no match 
	 */
	public abstract String getPassKey(String uri);
}
