package com.ezen.Dao;

import java.util.List;
import java.util.Map;

import javax.inject.Inject;

import org.apache.ibatis.session.SqlSession;
import org.springframework.stereotype.Repository;

import com.ezen.Other.Criteria;
import com.ezen.Vo.ASVO;
import com.ezen.Vo.boardVO;
import com.ezen.Vo.qnaVO;
import com.ezen.Vo.reportVO;

@Repository
public class myWroteListDAOImpl implements myWroteListDAO {

	@Inject
	private SqlSession sql;
	
	private static String namespace = "com.ezen.mappers.myWroteListMapper";
	
	@Override
	public List<boardVO> freeWroteList(Criteria cri) throws Exception {
		return sql.selectList(namespace + ".freeWroteList", cri);
	}

	@Override
	public int freeListCount() throws Exception {
		return sql.selectOne(namespace + ".freeListCount");
	}

	
	@Override
	public List<reportVO> reportWroteList(Criteria cri) throws Exception {
		return sql.selectList(namespace + ".reportWroteList", cri);
	}

	@Override
	public int reportListCount() throws Exception {
		return sql.selectOne(namespace + ".reportListCount");
	}

	
	@Override
	public List<qnaVO> qnaWroteList(Criteria cri) throws Exception {
		return sql.selectList(namespace + ".qnaWroteList", cri);
	}

	@Override
	public int qnaListCount() throws Exception {
		return sql.selectOne(namespace + ".qnaListCount");
	}

	@Override
	public Map<String, Object> selectFileInfo(Map<String, Object> map) throws Exception {
		return sql.selectOne(namespace + ".selectFileInfo", map);
	}

	@Override
	public List<ASVO> ASWroteList(Criteria cri) throws Exception{
		return sql.selectList(namespace + ".ASWroteList", cri);
	}
	
	@Override
	public int ASListCount() throws Exception{
		return sql.selectOne(namespace + ".ASListCount");
	}
}
