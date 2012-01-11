/* The MIT License
 *
 * Copyright (c) 2010-2011 www.myjeeva.com
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

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.securechannel.ChannelEntryPoint;
import org.springframework.security.util.PortMapper;
import org.springframework.security.util.PortMapperImpl;
import org.springframework.security.util.PortResolver;
import org.springframework.security.util.PortResolverImpl;
import org.springframework.util.Assert;

import com.myjeeva.spring.security.util.CrossDomainMapper;
import com.myjeeva.spring.security.util.CrossDomainMapperImpl;

/**
 * <code>AbstractCrossDomainRetryEntryPoint</code> provides provision to locate the cross domain name in the application context for respective ports defined in the {@link PortMapper}
 * while resolving server name before <code>HttpServletResponse#sendRedirect()</code> {@link CrossDomainMapper} provides the respective cross domain name.  
 * 
 * @author Jeevanandam (jeeva@myjeeva.com)
 */
public abstract class AbstractCrossDomainRetryEntryPoint implements ChannelEntryPoint {
	/** Logger */
	private static transient final Log LOG = LogFactory.getLog(AbstractCrossDomainRetryEntryPoint.class);
	private PortMapper portMapper = new PortMapperImpl();
	private CrossDomainMapper crossDomainMapper = new CrossDomainMapperImpl();
    private PortResolver portResolver = new PortResolverImpl();
    /** The scheme ("http://" or "https://") */
    private String scheme;
    /** The standard port for the scheme (80 for http, 443 for https) */
    private int standardPort;
	
    /**
     * Constructor 
     * 
     * @param scheme a {@link java.lang.String} object.
     * @param standardPort int - port #
     */
    public AbstractCrossDomainRetryEntryPoint(String scheme, int standardPort) {
        this.scheme = scheme;
        this.standardPort = standardPort;
    }	
    
    /**
     * {@inheritDoc}
     */
	public void commence(ServletRequest req, ServletResponse res) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        
        String pathInfo = request.getPathInfo();
        String queryString = request.getQueryString();
        String contextPath = request.getContextPath();
        String destination = request.getServletPath() + ((pathInfo == null) ? "" : pathInfo)
            + ((queryString == null) ? "" : ("?" + queryString));

        String redirectUrl = contextPath;

        Integer currentPort = new Integer(portResolver.getServerPort(request));
        Integer redirectPort = getMappedPort(currentPort);

        if (redirectPort != null) {
            boolean includePort = redirectPort.intValue() != standardPort;

            redirectUrl = scheme + getMappedDomain(request.getServerName()) + ((includePort) ? (":" + redirectPort) : "") + contextPath
                + destination;
        }

        LOG.debug(" Cross Domain EntryPoint Redirecting to: " + redirectUrl);

        ((HttpServletResponse) res).sendRedirect(((HttpServletResponse) res).encodeRedirectURL(redirectUrl));
    }
    
	/**
	 * gets the mapped port in application context
	 * 
	 * @param mapFromPort a {@link java.lang.Integer} object.
	 * @return port a {@link java.lang.Integer} object.
	 */
    protected abstract Integer getMappedPort(Integer mapFromPort);
    
    /**
     * gets the mapped domain name with respect to ports defined 
     * 
     * @param mapFromDomainName a {@link java.lang.String} object.
     * @return domain name a {@link java.lang.String} object.
     */
    protected abstract String getMappedDomain(String mapFromDomainName);
    
    /**
	 * @return the portMapper
	 */
	protected PortMapper getPortMapper() {
		return portMapper;
	}

	/**
	 * @return the portResolver
	 */
	protected PortResolver getPortResolver() {
		return portResolver;
	}

	/**
	 * @return the crossDomainMapper
	 */
	protected CrossDomainMapper getCrossDomainMapper() {
		return crossDomainMapper;
	}

	/**
	 * @param crossDomainMapper the crossDomainMapper to set
	 */
	public void setCrossDomainMapper(CrossDomainMapper crossDomainMapper) {
		Assert.notNull(crossDomainMapper, "crossDomainMapper cannot be null");
		this.crossDomainMapper = crossDomainMapper;
	}

	/**
	 * @param portMapper the portMapper to set
	 */
	public void setPortMapper(PortMapper portMapper) {
		Assert.notNull(portMapper, "portMapper cannot be null");
		this.portMapper = portMapper;
	}

	/**
	 * @param portResolver the portResolver to set
	 */
	public void setPortResolver(PortResolver portResolver) {
		Assert.notNull(portResolver, "portResolver cannot be null");
		this.portResolver = portResolver;
	}
}
