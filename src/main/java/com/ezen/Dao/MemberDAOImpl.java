package com.ezen.Dao;

import java.util.List;

import javax.inject.Inject;

import org.apache.ibatis.session.SqlSession;
import org.springframework.stereotype.Repository;

import com.ezen.Vo.MemberVO;

@Repository
public class MemberDAOImpl implements MemberDAO {
	 
	@Inject
	private SqlSession sql;
	
	private static String namespace = "com.ezen.mappers.memberMapper";
	
	@Override
	public void memberinsert(MemberVO vo) throws Exception {
		sql.insert(namespace + ".memberinsert", vo); 
	}
	
	@Override
	public MemberVO login(MemberVO vo) throws Exception {
		return sql.selectOne(namespace + ".login", vo);
	}
	@Override
	public MemberVO login_result(MemberVO vo) throws Exception {
		return sql.selectOne(namespace + ".login_result", vo);
	}
	
	@Override
	public void modify(MemberVO vo)throws Exception{
		sql.update(namespace +".modify", vo);
	}

	@Override
	public void withdrawal(MemberVO vo) throws Exception {
		sql.delete(namespace  +".withdrawal", vo);
	}
	
	@Override
	public MemberVO idCheck(String MEMBER_ID) throws Exception {
		return sql.selectOne(namespace  +".idCheck", MEMBER_ID);
		
	}
	@Override
	public String find_Id(MemberVO vo) throws Exception {
		return sql.selectOne(namespace + ".find_Id", vo);
	}

	@Override
	public String find_Pw(MemberVO vo) throws Exception {
		return sql.selectOne(namespace + ".find_Pw", vo);
	}

	@Override
	public List<MemberVO> list() throws Exception {
		return sql.selectList(namespace + ".list"); 
	}
	
	@Override
	public MemberVO memberdetail(String MEMBER_ID) throws Exception {
		return sql.selectOne(namespace + ".memberdetail", MEMBER_ID);
	}
	

	@Override
	public void memberdelete(String MEMBER_ID) throws Exception {
		sql.delete(namespace  +".memberdelete", MEMBER_ID);
	}

	@Override
	public void modifyPw(MemberVO vo)throws Exception{
		sql.update(namespace +".modifyPw", vo);
	}
	}
	