package com.ezen.Service;

import java.util.List;

import javax.inject.Inject;
import javax.servlet.http.HttpSession;

import org.springframework.stereotype.Service;

import com.ezen.Vo.MemberVO;
import com.ezen.Dao.MemberDAO;

@Service
public class MemberServiceImpl implements MemberService {
	
	@Inject
	private MemberDAO dao;
	
	@Override
	public void memberinsert(MemberVO vo) throws Exception {
		dao.memberinsert(vo);
	}
	
	@Override
	public MemberVO login(MemberVO vo) throws Exception {
		return dao.login(vo);
	}
	
	@Override
	public void logout(HttpSession session) throws Exception {
		session.invalidate();
	}
	

	@Override
	public MemberVO login_result(MemberVO vo) throws Exception {
		return dao.login_result(vo);
	}
	
	@Override
	public void modify(MemberVO vo) throws Exception{
		dao.modify(vo);
	}

	@Override
	public void withdrawal(MemberVO vo) throws Exception {
		dao.withdrawal(vo);
	}

	@Override
	public MemberVO idCheck(String MEMBER_ID) throws Exception {
		return dao.idCheck(MEMBER_ID);
	}
	@Override
	public String find_Id(MemberVO vo) throws Exception {
		return dao.find_Id(vo);
	}

	@Override
	public String find_Pw(MemberVO vo) throws Exception {
		return dao.find_Pw(vo);
	}
	
	@Override
	public List<MemberVO> list() throws Exception {
		return dao.list();
}
	@Override
	public MemberVO memberdetail(String MEMBER_ID) throws Exception {
		return dao.memberdetail(MEMBER_ID);
	}

	@Override
	public void memberdelete(String MEMBER_ID) throws Exception {
		dao.memberdelete(MEMBER_ID);
	}
		
	@Override
	public void modifyPw(MemberVO vo) throws Exception{
		dao.modifyPw(vo);
	}

	
	}
	


