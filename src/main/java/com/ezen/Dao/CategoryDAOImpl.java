package com.ezen.Dao;

import java.util.List;

import javax.inject.Inject;

import org.apache.ibatis.session.SqlSession;
import org.springframework.stereotype.Repository;

import com.ezen.Other.SearchCriteria;
import com.ezen.Vo.CategoryVO;
import com.ezen.Vo.GoodsDetailVO;
import com.ezen.Vo.GoodsVO;

@Repository
public class CategoryDAOImpl implements CategoryDAO {
	
	@Inject
	private SqlSession sql;
	
	
	// 매퍼
	private static String namespace = "com.ezen.mappers.categoryMapper";
	
	
	// 카테고리
	@Override
	public List<CategoryVO> category() throws Exception {
		return sql.selectList(namespace + ".category");
	}
	
	// 상품등록
	@Override
	public void goodswrite(GoodsVO vo) throws Exception {
		sql.insert(namespace + ".goodswrite", vo);
	}
	
	// 상품목록
	@Override
	public List<GoodsDetailVO> goodslist() throws Exception {
		return sql.selectList(namespace + ".goodslist"); 
	}
	
	// 목록 + 페이징 + 검색
	@Override
	public List<GoodsVO> goodslistSearch(SearchCriteria scri) throws Exception {
		return sql.selectList(namespace + ".goodslistSearch", scri);
		
		
	}
	
	
	// 검색 결과 횟수
	@Override
	public int countSearch(SearchCriteria scri) throws Exception {
		return sql.selectOne(namespace + ".countSearch", scri);
	}
	
	// 상품조회 + 카테고리와 조인
	@Override
	public GoodsDetailVO goodsdetail(int GOODS_NO) throws Exception {
		return sql.selectOne(namespace + ".goodsdetail", GOODS_NO);
	}

	@Override
	public void goodsModify(GoodsVO vo) throws Exception {
		sql.update(namespace + ".goodsModify", vo);
	}
	
	// 상품 삭제
	@Override
	public void goodsDelete(int GOODS_NO) throws Exception {
		
		sql.delete(namespace + ".goodsDelete", GOODS_NO);
	}
}
