package com.ezen.Service;

import java.util.List;

import javax.inject.Inject;

import org.springframework.stereotype.Service;

import com.ezen.Vo.GoodsDetailVO;
import com.ezen.Vo.GoodsVO;
import com.ezen.Vo.OrderListVO;
import com.ezen.Vo.ShopOrderVO;
import com.ezen.Vo.ShopReplyListVO;
import com.ezen.Dao.AdminDAO;
import com.ezen.Other.SearchCriteria;


@Service
public class AdminServiceImpl implements AdminService {
	
	@Inject
	private AdminDAO dao;
	
	// 주문 목록
	@Override
	public List<ShopOrderVO> orderList() throws Exception {
		return dao.orderList();
	}
		
	// 특정 주문 목록
	@Override
	public List<OrderListVO> orderView(ShopOrderVO order) throws Exception {
		return dao.orderView(order);
	}

	// 배송 상태
	@Override
	public void delivery(ShopOrderVO order) throws Exception {
		dao.delivery(order);
	}
	
	// 상품 목록
	@Override
	public List<GoodsDetailVO> goodslist() throws Exception {
		return dao.goodslist();
	}
	
	// 상품 조회
	@Override
	public GoodsDetailVO goodsdetail(int GOODS_NO) throws Exception {
		return dao.goodsdetail(GOODS_NO);
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
	
	
	// 모든 덧글 보기
	@Override
	public List<ShopReplyListVO> allReply() throws Exception {
		return dao.allReply();
	}
	
	// 덧글 삭제
	@Override
	public void deleteReply(int REP_NO) throws Exception {
		dao.deleteReply(REP_NO);
	}
}
