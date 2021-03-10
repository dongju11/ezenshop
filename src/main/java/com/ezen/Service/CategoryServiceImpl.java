package com.ezen.Service;

import java.util.List;

import javax.inject.Inject;

import org.springframework.stereotype.Service;

import com.ezen.Dao.CategoryDAO;
import com.ezen.Other.SearchCriteria;
import com.ezen.Vo.CategoryVO;
import com.ezen.Vo.GoodsDetailVO;
import com.ezen.Vo.GoodsVO;

@Service
public class CategoryServiceImpl implements CategoryService {

	@Inject
	private CategoryDAO dao;
	
	@Override
	public List<CategoryVO> category() throws Exception {
		return dao.category();
	}
	
	@Override
	public void goodswrite(GoodsVO vo) throws Exception {
		dao.goodswrite(vo);
	}
	
	@Override
	public List<GoodsDetailVO> goodslist() throws Exception {
		
		return dao.goodslist();
	}
	
	// 목록 + 페이징 + 검색
	@Override
	public List<GoodsVO> goodslistSearch(SearchCriteria scri) throws Exception {
		return dao.goodslistSearch(scri);
	}
	
	// 검색 결과 횟수
	@Override
	public int countSearch(SearchCriteria scri) throws Exception {
		return dao.countSearch(scri);
	}
	
	// 상품 조회
	@Override
	public GoodsDetailVO goodsdetail(int GOODS_NO) throws Exception {
		return dao.goodsdetail(GOODS_NO);
	}
	
	@Override
	public void goodsModify(GoodsVO vo) throws Exception {
		dao.goodsModify(vo);
	}
	
	@Override
	public void goodsDelete(int GOODS_NO) throws Exception {
		dao.goodsDelete(GOODS_NO);
	}
}
