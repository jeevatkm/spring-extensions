<%@page import="org.springframework.web.context.WebApplicationContext"%>
<%@page import="com.myjeeva.spring.security.secureuri.SecureUriProviderImpl"%>
<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>Secured URI/URL Demo: spring-extensions Library - www.myjeeva.com</title>
</head>
<body>
<center><h2>Welcome to Secured Link Demo</h2><br/><strong>spring-extensions Library</strong></center>
<p>Protecting Web Resource links/assets link [similar to Content Delivery Network(CDN) Secure Link concept] from End-user. myjeeva.com spring-extensions library provides mechanism to protect Dynamically</p>

<p>Here you see URI links below for valid and invalid request demo. First link is Dynamic secure link and Second link Static non-secure link.</p>
<%
	WebApplicationContext context = org.springframework.web.context.support.WebApplicationContextUtils.getWebApplicationContext(getServletContext());
	SecureUriProviderImpl uriProvider = (SecureUriProviderImpl)context.getBean("secureUriProvider");
	String url = uriProvider.generateSecureUri(request.getContextPath()+"/data/secure/index.jsp", 36000, "");
	String url2 = uriProvider.generateSecureUri(request.getContextPath()+"/protected/index.jsp", 0, "");
%>
	<ul>
		<li>Valid Protected URL (server will entertain this request): <a href="<% out.println(url); %>"><% out.println(url); %></a></li>
		<li>In-Valid URL (server will <strong>not</strong> entertain this request): <a href="<% out.println(request.getContextPath()); %>/data/secure/index.jsp"><% out.println(request.getContextPath()); %>/data/secure/index.jsp</a></li>
		<li>Valid Protected URL (server will entertain this request): <a href="<% out.println(url2); %>"><% out.println(url2); %></a></li>
		<li>In-Valid URL (server will <strong>not</strong> entertain this request): <a href="<% out.println(request.getContextPath()); %>/protected/index.jsp"><% out.println(request.getContextPath()); %>/protected/index.jsp</a></li>
	</ul>
</body>
</html>