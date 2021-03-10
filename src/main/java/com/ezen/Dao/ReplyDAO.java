package com.ezen.Dao;

import java.util.List;

import com.ezen.Vo.ReplyVO;

public interface ReplyDAO {
	
	public List<ReplyVO> readReply(int notice_no) throws Exception;
	
	// �뙎湲� �옉�꽦
	public void writeReply(ReplyVO vo) throws Exception;

	// �듅�젙 �뙎湲� 議고쉶
	public ReplyVO readReplySelect(int co_num) throws Exception;
	
	// �뙎湲� �닔�젙
	public void replyUpdate(ReplyVO vo) throws Exception;
		
	// �뙎湲� �궘�젣
	public void replyDelete(ReplyVO vo) throws Exception;
}
