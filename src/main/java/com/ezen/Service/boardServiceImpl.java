package com.ezen.Service;

import java.util.List;
import java.util.Map;

import javax.annotation.Resource;
import javax.inject.Inject;

import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartHttpServletRequest;

import com.ezen.Dao.boardDAO;
import com.ezen.Other.FileUtils;
import com.ezen.Other.SearchCriteria;
import com.ezen.Vo.boardVO;

@Repository
public class boardServiceImpl implements boardService {

	@Resource(name="fileUtils")
	private FileUtils fileUtils;
	
	@Inject
	private boardDAO dao;
	
	@Override
	public void write(boardVO vo, MultipartHttpServletRequest mpRequest) throws Exception {
		dao.write(vo);
		
		List<Map<String,Object>> list = fileUtils.parseInsertFileInfo(vo, mpRequest); 
		int size = list.size();
		for(int i=0; i<size; i++){ 
			dao.insertFile(list.get(i)); 
		}

	}

	@Transactional(isolation = Isolation.READ_COMMITTED)	
	@Override
	public boardVO read(int fr_no) throws Exception {
			dao.boardCount(fr_no);
		return dao.read(fr_no);
	}

	@Override
	public void update(boardVO vo, String[] files, String[] fileNames, MultipartHttpServletRequest mpRequest) throws Exception {
		dao.update(vo);
		
		List<Map<String, Object>> list = fileUtils.parseUpdateFileInfo(vo, files, fileNames, mpRequest);
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
	public void delete(int fr_no) throws Exception {
		dao.delete(fr_no);
	}

	@Override
	public List<boardVO> listSearch(SearchCriteria scri) throws Exception {
		return dao.listSearch(scri);
	}

	@Override
	public int countSearch(SearchCriteria scri) throws Exception {
		return dao.countSearch(scri);
	}

	@Override
	public List<Map<String, Object>> selectFileList(int fr_no) throws Exception {
		return dao.selectFileList(fr_no);
	}

	@Override
	public Map<String, Object> selectFileInfo(Map<String, Object> map) throws Exception {
		return dao.selectFileInfo(map);
	}

}
