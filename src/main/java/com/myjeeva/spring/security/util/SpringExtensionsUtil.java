/**
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
