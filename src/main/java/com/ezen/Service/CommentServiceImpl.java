package com.ezen.Service;

import java.util.List;

import javax.inject.Inject;

import org.springframework.stereotype.Repository;

import com.ezen.Dao.CommentDAO;
import com.ezen.Vo.CommentVO;

@Repository
public class CommentServiceImpl implements CommentService {

	@Inject
	private CommentDAO dao;
	
	@Override
	public List<CommentVO> comment(int fr_no) throws Exception {
		return dao.comment(fr_no);
	}

	@Override
	public void commentWrite(CommentVO vo) throws Exception {
		dao.commentWrite(vo);
	}

	@Override
	public CommentVO readComment(int comments_no) throws Exception {
		return dao.readComment(comments_no);
	}

	@Override
	public void commentModify(CommentVO vo) throws Exception {
		dao.commentModify(vo);
	}

	@Override
	public void commentDelete(CommentVO vo) throws Exception {
		dao.commentDelete(vo);
	}

	@Override
	public List<CommentVO> reportComment(int report_no) throws Exception {
		return dao.reportComment(report_no);
	}

	@Override
	public List<CommentVO> noticeComment(int notice_no) throws Exception {
		return dao.noticeComment(notice_no);
	}

	@Override
	public List<CommentVO> qnaComment(int qna_no) throws Exception {
		return dao.qnaComment(qna_no);
	}

}
