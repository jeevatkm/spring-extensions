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

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Date;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.Assert;

import com.myjeeva.spring.security.util.SecureUriMapper;
import com.myjeeva.spring.security.util.SpringExtensionsUtil;

/**
 * @author jeeva
 *
 */
public class SecureServerURI implements Filter {
	/** Logger */
	private static transient final Log LOG = LogFactory.getLog(SecureServerURI.class);
	private SecureUriMapper secureUriMapper;
	private static final String BAD_REQUEST = "<html><body><h1>Bad Request</h1></body></html>";
	
	/**
	 * @param secureUriMapper the secureUriMapper to set
	 */
	public void setSecureUriMapper(SecureUriMapper secureUriMapper) {
		Assert.notNull(secureUriMapper, "secureUriMapper cannot be null");
		this.secureUriMapper = secureUriMapper;
	}

	/**
     * {@inheritDoc}
     * 
     * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)
     */
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		
		HttpServletResponse res = (HttpServletResponse)response;
		HttpServletRequest req = (HttpServletRequest)request;
		
		String et = req.getParameter("e");
		String h = req.getParameter("h");
		
		if(null == et || null == h) {
			badRequest(res);
			LOG.warn("et & h attributes are null; Bad request from IP: " + req.getRemoteAddr());
			return;
		}
			
		String baseUrl = req.getRequestURI();
		String passKey = secureUriMapper.getPassKey(baseUrl);		
		
		String salt = passKey + baseUrl + "?e=" + et;
		String hash = SpringExtensionsUtil.getMD5(salt);		
		if(!hash.trim().equals(h)) {
			badRequest(res);
			LOG.warn("Hash Value doesn't match; Bad request from IP: " + req.getRemoteAddr());
			return;
		}
		
		long expiryTime = Long.parseLong(et);		
		if(expiryTime > 0 && !(new Date().getTime() <= expiryTime)) {
			badRequest(res);
			LOG.warn("Secure Link expried, link accessed from IP: " + req.getRemoteAddr());
			return;
		}		
		
		/** making chain call for following filters*/
		chain.doFilter(request, response);
	}

	/**
     * {@inheritDoc}
     * 
     * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
     */
	public void init(FilterConfig filterConfig) throws ServletException {		

	}

	/**
     * {@inheritDoc}
     * 
     * @see javax.servlet.Filter#destroy()
     */
	public void destroy() {		

	}
	
	private void badRequest(HttpServletResponse res) throws IOException {
		res.setContentType("text/html");
		PrintWriter pw = res.getWriter();
		pw.write(BAD_REQUEST);
		pw.close();
	}
}
