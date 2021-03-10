package com.ezen.Dao;

import java.util.List;
import java.util.Map;

import com.ezen.Other.SearchCriteria;
import com.ezen.Vo.boardVO;

public interface boardDAO {
	
	//입력
	public void write(boardVO vo) throws Exception;
	
	//상세보기
	public boardVO read(int fr_no) throws Exception;
	
	//수정
	public void update(boardVO vo) throws Exception;
	
	//삭제
	public void delete(int fr_no) throws Exception;
	
	//목록+검색
	public List<boardVO> listSearch(SearchCriteria scri) throws Exception;
	
	//페이지 수
	public int countSearch(SearchCriteria scri) throws Exception;
	
	//첨부파일 업로드
	public void insertFile(Map<String, Object> map) throws Exception;

	// 첨부파일 조회
	public List<Map<String, Object>> selectFileList(int fr_no) throws Exception;

	// 첨부파일 다운
	public Map<String, Object> selectFileInfo(Map<String, Object> map) throws Exception;

	// 첨부파일 수정
	public void updateFile(Map<String, Object> map) throws Exception;

	//게시판 조회수
	public void boardCount(int fr_no) throws Exception;
}
