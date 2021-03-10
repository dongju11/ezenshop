package com.ezen.Service;

import java.util.List;

import com.ezen.Vo.CommentVO;

public interface CommentService {

	//자유게시판 댓글조회
	public List<CommentVO> comment(int fr_no) throws Exception;
	
	//신고게시판
	public List<CommentVO> reportComment(int report_no) throws Exception;
	
	//공지사항
	public List<CommentVO> noticeComment(int notice_no) throws Exception;
	
	//문의사항
	public List<CommentVO> qnaComment(int qna_no) throws Exception;
	
	//댓글 작성
	public void commentWrite(CommentVO vo) throws Exception;
	
	//특정 댓글조회
	public CommentVO readComment(int comments_no) throws Exception;
	
	//댓글 수정
	public void commentModify(CommentVO vo) throws Exception;
	
	//댓글 삭제
	public void commentDelete(CommentVO vo) throws Exception;


}
