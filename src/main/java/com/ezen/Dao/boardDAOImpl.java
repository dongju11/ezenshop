package com.ezen.Dao;

import java.util.List;
import java.util.Map;

import javax.inject.Inject;

import org.apache.ibatis.session.SqlSession;
import org.springframework.stereotype.Repository;

import com.ezen.Other.SearchCriteria;
import com.ezen.Vo.boardVO;

@Repository
public class boardDAOImpl implements boardDAO {
	
	@Inject
	private SqlSession sql;
	
	private static String namespace = "com.ezen.mappers.freeBoardMapper";


	@Override
	public void write(boardVO vo) throws Exception {
		sql.insert(namespace + ".freeInsert", vo);
		
	}

	@Override
	public boardVO read(int fr_no) throws Exception {
		return sql.selectOne(namespace + ".freeSelect", fr_no);
	}

	@Override
	public void update(boardVO vo) throws Exception {
		sql.update(namespace + ".freeUpdate", vo);
	}

	@Override
	public void delete(int fr_no) throws Exception {
		sql.delete(namespace + ".freeDelete", fr_no);
		
	}

	@Override
	public List<boardVO> listSearch(SearchCriteria scri) throws Exception {
		return sql.selectList(namespace + ".boardList", scri);
	}

	@Override
	public int countSearch(SearchCriteria scri) throws Exception {
		return sql.selectOne(namespace + ".freeCountSearch", scri); 
	}

	@Override
	public void insertFile(Map<String, Object> map) throws Exception {
		sql.insert(namespace + ".insertFile", map);
	}

	@Override
	public List<Map<String, Object>> selectFileList(int fr_no) throws Exception {
		return sql.selectList(namespace + ".selectFileList", fr_no);
	}

	@Override
	public Map<String, Object> selectFileInfo(Map<String, Object> map) throws Exception {
		return sql.selectOne(namespace + ".selectFileInfo", map);
	}

	@Override
	public void updateFile(Map<String, Object> map) throws Exception {
		sql.update(namespace + ".updateFile", map);
	}

	@Override
	public void boardCount(int fr_no) throws Exception {
		sql.update(namespace + ".freeCount", fr_no);
	}


}
