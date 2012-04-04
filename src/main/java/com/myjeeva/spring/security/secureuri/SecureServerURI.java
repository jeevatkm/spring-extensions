/**
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
