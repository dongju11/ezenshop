package com.ezen.Service;

import java.util.List;
import java.util.Map;

import org.springframework.web.multipart.MultipartHttpServletRequest;

import com.ezen.Other.SearchCriteria;
import com.ezen.Vo.qnaVO;

public interface qnaService {

	//입력
	public void write(qnaVO vo, MultipartHttpServletRequest mpRequest) throws Exception;
		
	//상세보기
	public qnaVO read(int qna_no) throws Exception;
		
	//수정
	public void update(qnaVO vo, String[] files, String[] fileNames, MultipartHttpServletRequest mpRequest) throws Exception;
		
	//삭제
	public void delete(int qna_no) throws Exception;
		
	//검색, 목록
	public List<qnaVO> listSearch(SearchCriteria scri) throws Exception;
		
	//페이지
	public int countSearch(SearchCriteria scri) throws Exception; 

	// 첨부파일 조회
	public List<Map<String, Object>> selectFileList(int qna_no) throws Exception;

	// 첨부파일 다운
	public Map<String, Object> selectFileInfo(Map<String, Object> map) throws Exception;

}
