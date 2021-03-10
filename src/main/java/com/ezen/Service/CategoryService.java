package com.ezen.Service;

import java.util.List;

import com.ezen.Other.SearchCriteria;
import com.ezen.Vo.CategoryVO;
import com.ezen.Vo.GoodsDetailVO;
import com.ezen.Vo.GoodsVO;

public interface CategoryService {
	
	// 카테고리
	public List<CategoryVO> category() throws Exception;
	
	// 상품등록
	public void goodswrite(GoodsVO vo) throws Exception;
	
	// 상품목록
	public List<GoodsDetailVO> goodslist() throws Exception;
	
	// 목록 + 페이징 + 검색
	public List<GoodsVO> goodslistSearch(SearchCriteria scri) throws Exception;
	
	// 검색 결과 횟수
	public int countSearch(SearchCriteria scri) throws Exception;
	
	// 상품조회
	public GoodsDetailVO goodsdetail(int GOODS_NO) throws Exception;
		
	//상품 수정
	public void goodsModify(GoodsVO vo) throws Exception;
	
	// 상품 삭제
	public void goodsDelete(int GOODS_NO) throws Exception;
}
