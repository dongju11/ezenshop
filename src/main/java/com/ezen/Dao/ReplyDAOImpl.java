package com.ezen.Dao;

import java.util.List;

import javax.inject.Inject;

import org.apache.ibatis.session.SqlSession;
import org.springframework.stereotype.Repository;

import com.ezen.Vo.ReplyVO;

@Repository
public class ReplyDAOImpl implements ReplyDAO{
	
	@Inject
	private SqlSession sql;
	
	private static String namespace = "com.ezen.mappers.replyMapper";
	
	@Override
	public List<ReplyVO> readReply(int notice_no) throws Exception{
		return sql.selectList(namespace + ".readReply", notice_no);
	}

	// �뙎湲� �옉�꽦
	@Override
	public void writeReply(ReplyVO vo) throws Exception {
		sql.insert(namespace + ".writeReply", vo);		
	}


	// �듅�젙 �뙎湲� 議고쉶
	@Override
	public ReplyVO readReplySelect(int co_num) throws Exception {
		return sql.selectOne(namespace + ".readReplySelect", co_num);
	}
	
	// �뙎湲� �닔�젙
	@Override
	public void replyUpdate(ReplyVO vo) throws Exception {
		sql.update(namespace + ".updateReply", vo);
	}

	// �뙎湲� �궘�젣
	@Override
	public void replyDelete(ReplyVO vo) throws Exception {
		sql.delete(namespace + ".deleteReply", vo);
	}
}
