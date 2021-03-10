package com.ezen.Service;

import java.util.List;

import javax.inject.Inject;

import org.springframework.stereotype.Service;

import com.ezen.Dao.ReplyDAO;
import com.ezen.Vo.ReplyVO;

@Service
public class ReplyServiceImpl implements ReplyService
{
	@Inject
	private ReplyDAO dao;
	
	@Override
	public List<ReplyVO> readReply(int notice_no) throws Exception{
		return dao.readReply(notice_no);
	}
	
// ¥Ò±€ ¿€º∫
	@Override
	public void writeReply(ReplyVO vo) throws Exception {
		dao.writeReply(vo);		
	} 

	// ∆Ø¡§ ¥Ò±€ ¡∂»∏
	@Override
	public ReplyVO readReplySelect(int co_num) throws Exception {
		return dao.readReplySelect(co_num);
	}
	
	// ¥Ò±€ ºˆ¡§
	@Override
	public void replyUpdate(ReplyVO vo) throws Exception {
		dao.replyUpdate(vo);
	}

	// ¥Ò±€ ªË¡¶
	@Override
	public void replyDelete(ReplyVO vo) throws Exception {
		dao.replyDelete(vo);
	}
}
