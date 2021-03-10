package com.ezen.Dao;

import java.util.List;

import javax.inject.Inject;

import org.apache.ibatis.session.SqlSession;
import org.springframework.stereotype.Repository;

import com.ezen.Other.SearchCriteria;
import com.ezen.Vo.GoodsDetailVO;
import com.ezen.Vo.GoodsVO;
import com.ezen.Vo.OrderListVO;
import com.ezen.Vo.ShopOrderVO;
import com.ezen.Vo.ShopReplyListVO;

@Repository
public class AdminDAOImpl implements AdminDAO {
	
	@Inject
	private SqlSession sql;
	
	private static String namespace = "com.ezen.mappers.adminMapper";
	
	// 주문 목록
	@Override
	public List<ShopOrderVO> orderList() throws Exception {
		return sql.selectList(namespace + ".orderList");
	}
		
	// 특정 주문 목록
	@Override
	public List<OrderListVO> orderView(ShopOrderVO order) throws Exception {
		return sql.selectList(namespace + ".orderView", order);
	}
		
	// 배송 상태
	@Override
	public void delivery(ShopOrderVO order) throws Exception {
		sql.update(namespace + ".delivery", order);
	}
	
	// 상품 목록
	public List<GoodsDetailVO> goodslist() throws Exception {
		return sql.selectList(namespace + ".goodslist");
	}
	
	// 상품 조회
	public GoodsDetailVO goodsdetail(int GOODS_NO) throws Exception {
		return sql.selectOne(namespace + ".goodsdetail", GOODS_NO);
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
	
	// 모든 덧글 보기
	@Override
	public List<ShopReplyListVO> allReply() throws Exception {
		return sql.selectList(namespace + ".allReply");
	}
	
	// 덧글 삭제
	@Override
	public void deleteReply(int REP_NO) throws Exception {
		sql.delete(namespace + ".deleteReply", REP_NO);
	}

}
