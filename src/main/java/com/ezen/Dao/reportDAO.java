package com.ezen.Dao;

import java.util.List;
import java.util.Map;

import com.ezen.Other.SearchCriteria;

import com.ezen.Vo.reportVO;

public interface reportDAO {
	
	//입력
	public void write(reportVO vo) throws Exception;
	
	//상세보기
	public reportVO read(int report_no) throws Exception;
	
	//수정
	public void update(reportVO vo) throws Exception;
	
	//삭제
	public void delete(int report_no) throws Exception;
	
	//검색, 목록
	public List<reportVO> listSearch(SearchCriteria scri) throws Exception;
	
	//페이지
	public int countSearch(SearchCriteria scri) throws Exception; 
	
	//첨부파일 업로드
	public void insertFile(Map<String, Object> map) throws Exception;

	// 첨부파일 조회
	public List<Map<String, Object>> selectFileList(int report_no) throws Exception;

	// 첨부파일 다운
	public Map<String, Object> selectFileInfo(Map<String, Object> map) throws Exception;

	// 첨부파일 수정
	public void updateFile(Map<String, Object> map) throws Exception;
	
	//게시판 조회수
	public void reportCount(int report_no) throws Exception;
}
