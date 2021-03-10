package com.ezen.Dao;

import java.util.List;
import java.util.Map;

import javax.inject.Inject;

import org.apache.ibatis.session.SqlSession;
import org.springframework.stereotype.Repository;

import com.ezen.Other.SearchCriteria;
import com.ezen.Vo.reportVO;


@Repository
public class reportDAOImpl implements reportDAO{

	@Inject
	private SqlSession sql;
	
	private static String namespace = "com.ezen.mappers.reportBoardMapper";

	@Override
	public void write(reportVO vo) throws Exception {
		sql.insert(namespace + ".reportInsert", vo); 
	}

	@Override
	public reportVO read(int report_no) throws Exception {
		return sql.selectOne(namespace + ".reportSelect", report_no);
	}

	@Override
	public void update(reportVO vo) throws Exception {
		sql.update(namespace + ".reportUpdate", vo);
	}

	@Override
	public void delete(int report_no) throws Exception {
		sql.delete(namespace + ".reportDelete", report_no);
	}

	@Override
	public List<reportVO> listSearch(SearchCriteria scri) throws Exception {
		return sql.selectList(namespace + ".reportBoardList", scri);
	}

	@Override
	public int countSearch(SearchCriteria scri) throws Exception {
		return sql.selectOne(namespace + ".reportCountSearch", scri);
	}

	@Override
	public void insertFile(Map<String, Object> map) throws Exception {
		sql.insert(namespace + ".insertFile", map);		
	}

	@Override
	public List<Map<String, Object>> selectFileList(int report_no) throws Exception {
		return sql.selectList(namespace + ".selectFileList", report_no);
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
	public void reportCount(int report_no) throws Exception {
		sql.update(namespace + ".reportCount", report_no);
	}


	
}
