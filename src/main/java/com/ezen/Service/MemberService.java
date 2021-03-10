package com.ezen.Service;

import java.util.List;

import javax.servlet.http.HttpSession;

import com.ezen.Vo.MemberVO;

public interface MemberService {

	public void memberinsert(MemberVO vo) throws Exception;

	public MemberVO login(MemberVO vo) throws Exception;

	public void logout(HttpSession session) throws Exception;

	public MemberVO login_result(MemberVO vo) throws Exception;

	public void modify(MemberVO vo) throws Exception;

	public void withdrawal(MemberVO vo) throws Exception;

	public MemberVO idCheck(String MEMBER_ID) throws Exception;

	public String find_Id(MemberVO vo) throws Exception;

	public String find_Pw(MemberVO vo) throws Exception;

	public List<MemberVO> list() throws Exception;

	public MemberVO memberdetail(String MEMBER_ID) throws Exception;

	public void memberdelete(String MEMBER_ID) throws Exception;
	
	public void modifyPw(MemberVO vo) throws Exception;


}
