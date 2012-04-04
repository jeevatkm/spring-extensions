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

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * @author jeeva
 *
 */
public class SpringExtensionsUtil {
	/** Logger */
	private static transient final Log LOG = LogFactory.getLog(SpringExtensionsUtil.class);
	
	/**
	 * static Constants
	 */
	private static final String UTF8 = "UTF-8";	
	private static final String MD5 = "MD5";

	/**
	 * generates the MD5 Hash value from given salt value
	 * 
	 * @param md5Salt - a {@link java.lang.String} object.
	 * @return md5 hash value if success, <code>null</code> if exception/fails
	 */
	public static String getMD5(String md5Salt) {
		try {
			MessageDigest md = MessageDigest.getInstance(MD5);
			byte[] array = md.digest(md5Salt.getBytes(UTF8));
			StringBuffer sb = new StringBuffer();
			for (int i = 0; i < array.length; ++i) {
				sb.append(Integer.toHexString((array[i] & 0xFF) | 0x100).substring(1, 3));
			}
			return sb.toString();
		} catch (java.security.NoSuchAlgorithmException e) {
			LOG.error(e.getMessage());
		} catch (UnsupportedEncodingException e) {
			LOG.error(e.getMessage());
		}
		return null;
	}
}
