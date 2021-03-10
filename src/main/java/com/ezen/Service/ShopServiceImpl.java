package com.ezen.Service;

import java.util.List;

import javax.inject.Inject;

import org.springframework.stereotype.Service;

import com.ezen.Dao.ShopDAO;
import com.ezen.Vo.CartListVO;
import com.ezen.Vo.CartVO;
import com.ezen.Vo.GoodsDetailVO;
import com.ezen.Vo.GoodsVO;
import com.ezen.Vo.JjimListVO;
import com.ezen.Vo.JjimVO;
import com.ezen.Vo.OrderListVO;
import com.ezen.Vo.ShopOrderDetailVO;
import com.ezen.Vo.ShopOrderVO;
import com.ezen.Vo.ShopReplyListVO;
import com.ezen.Vo.ShopReplyVO;

@Service
public class ShopServiceImpl implements ShopService {
			
	@Inject
	private ShopDAO dao;
	
	@Override
	public List<GoodsDetailVO> list(int GOODS_CATEGORY, int level) throws Exception {
		
		int CATECODEREF = 0;
		
		if(level == 1) {
			
			CATECODEREF = GOODS_CATEGORY;
			return dao.list(GOODS_CATEGORY, CATECODEREF);
		} else {
			return dao.list(GOODS_CATEGORY);
		}
		
		
	}
	
	@Override
	public GoodsDetailVO goodsdetail(int GOODS_NO) throws Exception {
		
		return dao.goodsdetail(GOODS_NO);
	}
	
	// �긽�뭹 �뙎湲� �옉�꽦
	@Override
	public void registReply(ShopReplyVO reply) throws Exception {
		dao.registReply(reply);
	}

	// �긽�뭹 由ъ뒪�듃
	@Override
	public List<ShopReplyListVO> replyList(int GOODS_NO) throws Exception {
		return dao.replyList(GOODS_NO);
	}
	
	
	// �옣諛붽뎄�땲 �떞湲�
	@Override
	public void addCart(CartListVO cart) throws Exception {
		dao.addCart(cart);
	}
	
	// �옣諛붽뎄�땲 由ъ뒪�듃
	@Override
	public List<CartListVO> cartList(String MEMBER_ID) throws Exception {
		return dao.cartList(MEMBER_ID);
	}
	// �옣諛붽뎄�땲 �궘�젣
	@Override
	public void deleteCart(CartVO cart) throws Exception {
		dao.deleteCart(cart);
	}
	
	// 二쇰Ц �젙蹂�
	@Override
	public void orderInfo(ShopOrderVO order) throws Exception {
		dao.orderInfo(order);
	}
		
	// 二쇰Ц �긽�꽭 �젙蹂�
	@Override
	public void orderInfo_Details(ShopOrderDetailVO shopOrderDetail) throws Exception {
		dao.orderInfo_Details(shopOrderDetail);
	}
	
	// �옣諛붽뎄�땲 鍮꾩슦湲�
	@Override
	public void cartAllDelete(String MEMBER_ID) throws Exception {
		dao.cartAllDelete(MEMBER_ID);
	}
	
	@Override
	// 二쇰Ц 紐⑸줉
	public List<ShopOrderVO> orderList(ShopOrderVO order) throws Exception {
		return dao.orderList(order);
	}
	
	// �굹�쓽 二쇰Ц 紐⑸줉
	@Override
	public List<ShopOrderVO> myorderList(ShopOrderVO order) throws Exception {
		return dao.myorderList(order);
	}
	
	@Override
	// �듅�젙 二쇰Ц 紐⑸줉
	public List<OrderListVO> orderView(ShopOrderVO order) throws Exception {
		return dao.orderView(order);
	}

	@Override
	public int addJjim(JjimListVO jjim) throws Exception {
		
		if(0 < dao.findJjim(jjim)) {
			return 0;
		}
		return dao.addJjim(jjim);
	}

	@Override
	public List<JjimListVO> jjimList(String MEMBER_ID) throws Exception {
		return dao.jjimList(MEMBER_ID);
	}

	@Override
	public void deleteJjim(JjimVO jjim) throws Exception {
		dao.deleteJjim(jjim);
	}

	@Override
	public void jjimAllDelete(String MEMBER_ID) throws Exception {
		dao.jjimAllDelete(MEMBER_ID);
	}
	
	@Override
	public List<GoodsVO> newGoods() throws Exception {
		return dao.newGoods();
	}

	@Override
	public List<GoodsVO> bestGoods() throws Exception {
		return dao.bestGoods();
	}
}
