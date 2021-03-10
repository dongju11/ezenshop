package com.ezen.Dao;

import java.util.List;

import com.ezen.Other.SearchCriteria;
import com.ezen.Vo.CategoryVO;
import com.ezen.Vo.GoodsDetailVO;
import com.ezen.Vo.GoodsVO;


public interface CategoryDAO {
	
	public List<CategoryVO> category() throws Exception;

	public void goodswrite(GoodsVO vo) throws Exception;
	
	public List<GoodsDetailVO> goodslist() throws Exception;
	
	// 목록 + 페이징 + 검색
	public List<GoodsVO> goodslistSearch(SearchCriteria scri) throws Exception;
	
	// 검색 결과 횟수
	public int countSearch(SearchCriteria scri) throws Exception;
	
	public GoodsDetailVO goodsdetail(int GOODS_NO) throws Exception;
	
	public void goodsModify(GoodsVO vo) throws Exception;
	
	public void goodsDelete(int GOODS_NO) throws Exception;
}
