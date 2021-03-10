package com.ezen.Service;

import com.ezen.Vo.NoticeVO;
import com.ezen.Other.SearchCriteria;

import java.util.List;
import java.util.Map;

import org.springframework.web.multipart.MultipartHttpServletRequest;

public interface NoticeService {
	
	public void write(NoticeVO vo, MultipartHttpServletRequest mpRequest) throws Exception;
	
	public NoticeVO read(int notice_no) throws Exception;
	
	public void update(NoticeVO vo, String[] files, String[] fileNames, MultipartHttpServletRequest mpRequest) throws Exception;
	
	public void delete(int notice_no) throws Exception;
	
	public List<NoticeVO> listSearch(SearchCriteria scri) throws Exception;
	
	public int countSearch(SearchCriteria scri) throws Exception;
	//첨부파일 조회
	public List<Map<String, Object>> selectFileList(int notice_no) throws Exception;
	
	public Map<String, Object> selectFileInfo(Map<String, Object> map) throws Exception;
}

