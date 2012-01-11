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
package com.myjeeva.spring.security.util;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.springframework.security.util.PortMapper;
import org.springframework.util.Assert;

/**
 * Concrete implementation of {@link CrossDomainMapper} that obtains HTTP domain:HTTPS domain pairs from the application context.
 * <p>
 * So map the all the cross domain name entry in the application context for respective ports defined in the {@link PortMapper}
 *
 * @author Jeevanandam (jeeva@myjeeva.com)
 */
public class CrossDomainMapperImpl implements CrossDomainMapper {
	
	private Map crossDomainMappings;
	
	public CrossDomainMapperImpl() {
		crossDomainMappings = new HashMap();		
	}
	
	/**
     * Returns the translated (cross domain name -> cross domain name) version of the respective cross domain name mapping specified via
     * {@link CrossDomainMapperImpl#setCrossDomainMappings(Map)}
     */
	public Map getTranslatedPortMappings() {
		return crossDomainMappings;
	}
	
	/**
	 * returns the HTTP domain Name
	 */
	public String lookupHttpCrossDomain(String httpsDomainName) {
		Iterator iter = crossDomainMappings.keySet().iterator();

        while (iter.hasNext()) {
        	String httpDomainName = (String) iter.next();

            if (crossDomainMappings.get(httpDomainName).equals(httpsDomainName)) {
                return httpDomainName;
            }
        }

        return null;
	}

	/**
	 * returns the HTTPS domain name
	 */
	public String lookupHttpsCrossDomain(String httpDomainName) {
		return (String) crossDomainMappings.get(httpDomainName);
	}
	
	/**
     * Set to map the cross domain respectively to port mappings defined in the {@link PortMapper}
     * In a Spring XML ApplicationContext, a definition would look something like this:
     * <pre>
     *  &lt;property name="crossDomainMappings">
     *      &lt;map>
     *          &lt;entry key="company.com">&lt;value>sso.company.com&lt;/value>&lt;/entry>
     *          &lt;entry key="internal.company.com">&lt;value>auth.internal.company.com&lt;/value>&lt;/entry>
     *      &lt;/map>
     * &lt;/property></pre>
     *
     * @param newCrossDomainMappings - A Map consisting of String keys and String values, where for each entry the key is the string
     *        representation of an HTTP cross domain, and the value is the string representation of the corresponding integer HTTPS cross domain.
     *
     * @throws IllegalArgumentException if input map does not consist of String keys and values.
     */
    public void setCrossDomainMappings(Map newCrossDomainMappings) {
        Assert.notNull(newCrossDomainMappings, "A valid list of HTTPS cross domain name mappings must be provided");

        crossDomainMappings.clear();

        Iterator it = newCrossDomainMappings.entrySet().iterator();

        while (it.hasNext()) {
            Map.Entry entry = (Map.Entry) it.next();
            crossDomainMappings.put((String) entry.getKey(), (String) entry.getValue());
        }

        if (crossDomainMappings.size() < 1) {
            throw new IllegalArgumentException("must map at least one cross domain name");
        }
    }
}
