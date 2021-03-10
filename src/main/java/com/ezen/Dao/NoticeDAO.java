package com.ezen.Dao;

import com.ezen.Vo.NoticeVO;
import com.ezen.Other.SearchCriteria;


import java.util.List;
import java.util.Map;

public interface NoticeDAO {
	
	public void write(NoticeVO vo) throws Exception;
	
	public NoticeVO read(int notice_no) throws Exception;
	
	public void update(NoticeVO vo) throws Exception;
	
	public void delete(int notice_no) throws Exception;

	public List<NoticeVO> listSearch(SearchCriteria scri) throws Exception;
	
	public int countSearch(SearchCriteria scri) throws Exception;

	public void insertFile(Map<String, Object> map) throws Exception;
	//첨부파일 조회
	public List<Map<String, Object>> selectFileList(int notice_no) throws Exception;
	
	public Map<String, Object> selectFileInfo(Map<String, Object> map) throws Exception;

	// 파일 업데이트
	public void updateFile(Map<String, Object> map) throws Exception;
	
	public void noticeCount(int notice_no) throws Exception;
}
