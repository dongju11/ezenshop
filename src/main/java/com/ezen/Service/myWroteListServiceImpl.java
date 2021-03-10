package com.ezen.Service;

import java.util.List;
import java.util.Map;

import javax.inject.Inject;

import org.springframework.stereotype.Repository;

import com.ezen.Dao.myWroteListDAO;
import com.ezen.Other.Criteria;
import com.ezen.Vo.ASVO;
import com.ezen.Vo.boardVO;
import com.ezen.Vo.qnaVO;
import com.ezen.Vo.reportVO;

@Repository
public class myWroteListServiceImpl implements myWroteListService {

	@Inject
	private myWroteListDAO dao;
	
	
	@Override
	public List<boardVO> freeWroteList(Criteria cri) throws Exception {
		return dao.freeWroteList(cri);
	}

	@Override
	public int freeListCount() throws Exception {
		return dao.freeListCount();
	}
	
	@Override
	public List<reportVO> reportWroteList(Criteria cri) throws Exception {
		return dao.reportWroteList(cri);
	}

	@Override
	public int reportListCount() throws Exception {
		return dao.reportListCount();
	}
	
	@Override
	public List<qnaVO> qnaWroteList(Criteria cri) throws Exception {
		return dao.qnaWroteList(cri);
	}

	@Override
	public int qnaListCount() throws Exception {
		return dao.qnaListCount();
	}

	@Override
	public Map<String, Object> selectFileInfo(Map<String, Object> map) throws Exception {
		return dao.selectFileInfo(map);
	}
	
	@Override
	public List<ASVO> ASWroteList(Criteria cri) throws Exception{
		return dao.ASWroteList(cri);
	}
	
	@Override
	public int ASListCount() throws Exception{
		return dao.ASListCount();
	}
}
