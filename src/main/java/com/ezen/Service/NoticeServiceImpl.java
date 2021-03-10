package com.ezen.Service;

import java.util.List;
import java.util.Map;

import javax.annotation.Resource;
import javax.inject.Inject;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartHttpServletRequest;
import com.ezen.Vo.NoticeVO;
import com.ezen.Other.SearchCriteria;
import com.ezen.Other.noticeFileUtils;

import com.ezen.Dao.NoticeDAO;


@Service
public class NoticeServiceImpl implements NoticeService{
	
	@Resource(name="noticeFileUtils")
	private noticeFileUtils noticeFileUtils;
	
	@Inject
	private NoticeDAO dao;
	
	
	@Override
	public void write(NoticeVO vo, MultipartHttpServletRequest mpRequest) throws Exception{
		dao.write(vo);
		
		List<Map<String,Object>> list = noticeFileUtils.parseInsertFileInfo(vo, mpRequest);
		int size = list.size();
		for(int i =0; i<size; i++) {
			dao.insertFile(list.get(i));
		}
	}
	
	@Transactional(isolation = Isolation.READ_COMMITTED)
	@Override
	public NoticeVO read(int notice_no) throws Exception{
		dao.noticeCount(notice_no);
		return dao.read(notice_no);
	}
	
	@Override
	public void update(NoticeVO vo, String[] files, String[] fileNames, MultipartHttpServletRequest mpRequest) throws Exception{
		dao.update(vo);
		
		//파일 수정하기
		List<Map<String, Object>> list = noticeFileUtils.parseUpdateFileInfo(vo, files, fileNames, mpRequest);
		Map<String, Object> tempMap = null;
		int size = list.size();
		for(int i = 0; i<size; i++) {
			tempMap = list.get(i);
			if(tempMap.get("IS_NEW").equals("Y")) {
				dao.insertFile(tempMap);
			}else {
				dao.updateFile(tempMap);
			}
		}
	}
	
	@Override
	public void delete(int notice_no) throws Exception{
		dao.delete(notice_no);
	}
	

	@Override
	public List<NoticeVO> listSearch(SearchCriteria scri) throws Exception {
		return dao.listSearch(scri);
	}

	@Override
	public int countSearch(SearchCriteria scri) throws Exception {
		return dao.countSearch(scri);
	}
	//파일 목록
	@Override
	public List<Map<String,Object>> selectFileList(int notice_no) throws Exception{
		return dao.selectFileList(notice_no);
	}
	//첨부파일 다운로드
	@Override
	public Map<String, Object> selectFileInfo(Map<String, Object> map) throws Exception {
		return dao.selectFileInfo(map);
	}
}
