package com.ezen.Dao;

import java.util.List;

import com.ezen.Other.SearchCriteria;
import com.ezen.Vo.GoodsDetailVO;
import com.ezen.Vo.GoodsVO;
import com.ezen.Vo.OrderListVO;
import com.ezen.Vo.ShopOrderVO;
import com.ezen.Vo.ShopReplyListVO;

public interface AdminDAO {

	// 주문 목록
	public List<ShopOrderVO> orderList() throws Exception;
	
	// 특정 주문 목록
	public List<OrderListVO> orderView(ShopOrderVO order) throws Exception;
	
	// 배송 상태
	public void delivery(ShopOrderVO order) throws Exception;
	
	// 상품 목록
	public List<GoodsDetailVO> goodslist() throws Exception;
	
	// 상품 조회
	public GoodsDetailVO goodsdetail(int GOODS_NO) throws Exception;
	
	// 목록 + 페이징 + 검색
	public List<GoodsVO> goodslistSearch(SearchCriteria scri) throws Exception;
	
	// 검색 결과 횟수
	public int countSearch(SearchCriteria scri) throws Exception;
	
	// 모든 덧글 보기
	public List<ShopReplyListVO> allReply() throws Exception;
	
	// 덧글 삭제
	public void deleteReply(int REP_NO) throws Exception;
}
