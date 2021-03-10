package com.ezen.Dao;

import java.util.List;

import com.ezen.Other.Criteria;
import com.ezen.Vo.ASVO;

public interface ASDAO
{
	//보기
	public void see() throws Exception;
	// 작성
	public void write(ASVO vo) throws Exception;
	// 조회
	public ASVO read(int as_no) throws Exception;
	// 수정
	public void update(ASVO vo) throws Exception;
	// 삭제
	public void delete(int as_no) throws Exception;
	//목록
	public List<ASVO> list(Criteria cri) throws Exception;
	//게시물 총 개수
	public int listCount() throws Exception;
}
