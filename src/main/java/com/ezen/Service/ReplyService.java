package com.ezen.Service;

import java.util.List;

import com.ezen.Vo.ReplyVO;

public interface ReplyService {
	
	public List<ReplyVO> readReply(int notice_no) throws Exception;
	
	// 占쎈솊疫뀐옙 占쎌삂占쎄쉐
	public void writeReply(ReplyVO vo) throws Exception;

	// 占쎈뱟占쎌젟 占쎈솊疫뀐옙 鈺곌퀬�돳
	public ReplyVO readReplySelect(int co_num) throws Exception;
	
	// 占쎈솊疫뀐옙 占쎈땾占쎌젟
	public void replyUpdate(ReplyVO vo) throws Exception;
		
	// 占쎈솊疫뀐옙 占쎄텣占쎌젫
	public void replyDelete(ReplyVO vo) throws Exception;
}
