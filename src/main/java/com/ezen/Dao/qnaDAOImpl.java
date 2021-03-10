package com.ezen.Dao;

import java.util.List;
import java.util.Map;

import javax.inject.Inject;

import org.apache.ibatis.session.SqlSession;
import org.springframework.stereotype.Repository;

import com.ezen.Other.SearchCriteria;
import com.ezen.Vo.qnaVO;

@Repository
public class qnaDAOImpl implements qnaDAO {

	@Inject
	private SqlSession sql;
	
	private static String namespace = "com.ezen.mappers.qnaBoardMapper";
	
	@Override
	public void write(qnaVO vo) throws Exception {
		sql.insert(namespace + ".qnaInsert", vo);
	}

	@Override
	public qnaVO read(int qna_no) throws Exception {
		return sql.selectOne(namespace + ".qnaSelect", qna_no);
	}

	@Override
	public void update(qnaVO vo) throws Exception {
		sql.update(namespace + ".qnaUpdate", vo);
	}

	@Override
	public void delete(int qna_no) throws Exception {
		sql.delete(namespace + ".qnaDelete", qna_no);
	}

	@Override
	public List<qnaVO> listSearch(SearchCriteria scri) throws Exception {
		return sql.selectList(namespace + ".qnaBoardList", scri);
	}

	@Override
	public int countSearch(SearchCriteria scri) throws Exception {
		return sql.selectOne(namespace + ".qnaCountSearch", scri);
	}

	@Override
	public void insertFile(Map<String, Object> map) throws Exception {
		sql.insert(namespace + ".insertFile", map);
	}

	@Override
	public List<Map<String, Object>> selectFileList(int qna_no) throws Exception {
		return sql.selectList(namespace + ".selectFileList", qna_no);
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
	public void qnaCount(int qna_no) throws Exception {
		sql.update(namespace + ".qnaCount", qna_no);
	}

}
