package com.ezen.Service;

import java.util.List;
import java.util.Map;

import javax.annotation.Resource;
import javax.inject.Inject;

import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartHttpServletRequest;

import com.ezen.Dao.qnaDAO;
import com.ezen.Other.SearchCriteria;
import com.ezen.Other.qnaFileUtils;
import com.ezen.Vo.qnaVO;

@Repository
public class qnaServiceImpl implements qnaService {

	@Resource(name="qnaFileUtils")
	private qnaFileUtils qnaFileUtils;
	
	@Inject
	private qnaDAO dao;
	
	//글쓰기
	@Override 
	public void write(qnaVO vo, MultipartHttpServletRequest mpRequest) throws Exception {
		dao.write(vo);
		
		//파일추가
		List<Map<String,Object>> list = qnaFileUtils.parseInsertFileInfo(vo, mpRequest); 
		int size = list.size();
		for(int i=0; i<size; i++){ 
			dao.insertFile(list.get(i));
		}	
	}

	//상세보기
	@Transactional(isolation = Isolation.READ_COMMITTED)
	@Override
	public qnaVO read(int qna_no) throws Exception {
			dao.qnaCount(qna_no);
		return dao.read(qna_no);
	}

	//수정
	@Override
	public void update(qnaVO vo, String[] files, String[] fileNames, MultipartHttpServletRequest mpRequest)
			throws Exception {
		dao.update(vo);
		
		//파일수정
		List<Map<String, Object>> list = qnaFileUtils.parseUpdateFileInfo(vo, files, fileNames, mpRequest);
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

	//글삭제
	@Override
	public void delete(int qna_no) throws Exception {
		dao.delete(qna_no);
	}

	//글목록, 검색
	@Override
	public List<qnaVO> listSearch(SearchCriteria scri) throws Exception {
		return dao.listSearch(scri);
	}
	
	//페이지
	@Override
	public int countSearch(SearchCriteria scri) throws Exception {
		return dao.countSearch(scri);
	}
	
	//첨부파일파일 조회
	@Override
	public List<Map<String, Object>> selectFileList(int qna_no) throws Exception {
		return dao.selectFileList(qna_no);
	}

	//첨부파일 다운
	@Override
	public Map<String, Object> selectFileInfo(Map<String, Object> map) throws Exception {
		return dao.selectFileInfo(map);
	}
}
