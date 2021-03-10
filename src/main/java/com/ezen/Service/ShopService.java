package com.ezen.Service;

import java.util.List;

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

public interface ShopService {
	
	// �긽�뭹 由ъ뒪�듃
	public List<GoodsDetailVO> list(int GOODS_CATEGORY, int level) throws Exception;
	// �긽�뭹 議고쉶
	public GoodsDetailVO goodsdetail(int GOODS_NO) throws Exception;
	
	public void registReply(ShopReplyVO reply) throws Exception; 
	
	public List<ShopReplyListVO> replyList(int GOODS_NO) throws Exception;
	
	public void addCart(CartListVO cart) throws Exception;
	//�옣諛붽뎄�땲 由ъ뒪�듃
	public List<CartListVO> cartList(String MEMBER_ID) throws Exception;
	//�옣諛붽뎄�땲 �궘�젣
	public void deleteCart(CartVO cart) throws Exception;
	// 二쇰Ц �젙蹂�
	public void orderInfo(ShopOrderVO order) throws Exception;
		
	// 二쇰Ц �긽�꽭 �젙蹂�
	public void orderInfo_Details(ShopOrderDetailVO shopOrderDetail) throws Exception;
	
	// �옣諛붽뎄�땲 鍮꾩슦湲�
	public void cartAllDelete(String MEMBER_ID) throws Exception;
	
	// 二쇰Ц 紐⑸줉
	public List<ShopOrderVO> orderList(ShopOrderVO order) throws Exception;
	
	// �굹�쓽 二쇰Ц 紐⑸줉
	public List<ShopOrderVO> myorderList(ShopOrderVO order) throws Exception;
	
	// �듅�젙 二쇰Ц 紐⑸줉
	public List<OrderListVO> orderView(ShopOrderVO order) throws Exception;
	
	//찜하기
	public int addJjim(JjimListVO jjim) throws Exception;
	
	public List<JjimListVO> jjimList(String MEMBER_ID) throws Exception;
		
	public void deleteJjim(JjimVO jjim) throws Exception;
	
	public void jjimAllDelete(String MEMBER_ID) throws Exception;	

	public List<GoodsVO> newGoods() throws Exception;
	
	public List<GoodsVO> bestGoods() throws Exception;
}
