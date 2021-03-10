package com.ezen.Dao;

import java.util.List;

import javax.inject.Inject;

import org.apache.ibatis.session.SqlSession;
import org.springframework.stereotype.Repository;

import com.ezen.Vo.CommentVO;

@Repository
public class CommentDAOImpl implements CommentDAO {

	@Inject
	private SqlSession sql;
	
	private static String namespace = "com.ezen.mappers.commentsMapper";
	
	@Override
	public List<CommentVO> comment(int fr_no) throws Exception {
		return sql.selectList(namespace + ".freeboardSelect", fr_no);
	}
	@Override
	public void commentWrite(CommentVO vo) throws Exception {
		sql.insert(namespace + ".commentInsert", vo); 
	}
	@Override
	public CommentVO readComment(int comments_no) throws Exception {
		return sql.selectOne(namespace + ".readComment", comments_no);
	}
	@Override
	public void commentModify(CommentVO vo) throws Exception {
		sql.update(namespace + ".commentModify", vo);
	}
	@Override
	public void commentDelete(CommentVO vo) throws Exception {
		sql.delete(namespace + ".commentDelete", vo);
	}
	@Override
	public List<CommentVO> reportComment(int report_no) throws Exception {
		return sql.selectList(namespace + ".reportboardSelect", report_no);
	}
	@Override
	public List<CommentVO> noticeComment(int notice_no) throws Exception {
		return sql.selectList(namespace + ".noticeboardSelect", notice_no);
	}
	@Override
	public List<CommentVO> qnaComment(int qna_no) throws Exception {
		return sql.selectList(namespace + ".qnaboardSelect", qna_no);
	}
	
}