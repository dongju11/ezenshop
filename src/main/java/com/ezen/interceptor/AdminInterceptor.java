package com.ezen.interceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import com.ezen.Vo.MemberVO;

public class AdminInterceptor extends HandlerInterceptorAdapter {
	
	@Override
	 public boolean preHandle(HttpServletRequest req,
	    HttpServletResponse res, Object obj) throws Exception {
	  
	  HttpSession session = req.getSession();
	  MemberVO member = (MemberVO)session.getAttribute("member");
	  
	  if(member == null || member.getMEMBER_VERIFY() != 1) {
	   res.sendRedirect("/");
	   return false;
	  }
	  
	  return true;
	 }

}
