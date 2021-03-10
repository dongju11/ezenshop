package com.ezen.Dao;

import java.util.HashMap;
import java.util.List;

import javax.inject.Inject;

import org.apache.ibatis.session.SqlSession;
import org.springframework.stereotype.Repository;

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

@Repository
public class ShopDAOImpl implements ShopDAO {
	
	@Inject
	private SqlSession sql;
	
	private static String namespace = "com.ezen.mappers.shopMapper";
	
	@Override
	public List<GoodsDetailVO> list(int GOODS_CATEGORY, int CATECODEREF) throws Exception {
			
		HashMap<String, Object> map = new HashMap<String, Object>();
		
		map.put("GOODS_CATEGORY", GOODS_CATEGORY);
		map.put("CATECODEREF", CATECODEREF);
		
		return sql.selectList(namespace + ".list_1", map); 
	}
	
	
	@Override
	public List<GoodsDetailVO> list(int GOODS_CATEGORY) throws Exception {
		
		return sql.selectList(namespace + ".list_2", GOODS_CATEGORY);
		
	}
	
	//�긽�뭹 議고쉶
	@Override
	public GoodsDetailVO goodsdetail(int GOODS_NO) throws Exception {
		return sql.selectOne("com.ezen.mappers.categoryMapper" + ".goodsdetail", GOODS_NO);
	}
	
	
	// �긽�뭹 �뙎湲� �옉�꽦
	@Override
	public void registReply(ShopReplyVO reply) throws Exception {
		sql.insert(namespace + ".registReply", reply);
	}
	
	// �긽�뭹 �뜤湲� 由ъ뒪�듃
	@Override
	public List<ShopReplyListVO> replyList(int GOODS_NO) throws Exception {
		return sql.selectList(namespace + ".replyList", GOODS_NO);
	}

	
	@Override
	public void addCart(CartListVO cart) throws Exception {
		sql.insert(namespace + ".addCart", cart);
	}
	
	// �옣諛붽뎄�땲 由ъ뒪�듃
	@Override
	public List<CartListVO> cartList(String MEMBER_ID) throws Exception {
		return sql.selectList(namespace + ".cartList", MEMBER_ID);
	}
	
	// �옣諛붽뎄�땲 �궘�젣
	@Override
	public void deleteCart(CartVO cart) throws Exception {
		sql.delete(namespace + ".deleteCart", cart);
	}
	
	// 二쇰Ц �젙蹂�
	@Override
	public void orderInfo(ShopOrderVO order) throws Exception {
		sql.insert(namespace + ".orderInfo", order);
	}
		
	// 二쇰Ц �긽�꽭 �젙蹂�
	@Override
	public void orderInfo_Details(ShopOrderDetailVO shopOrderDetail) throws Exception {
		sql.insert(namespace + ".orderInfo_Details", shopOrderDetail);		
	}
	
	@Override
	// �옣諛붽뎄�땲 鍮꾩슦湲�
	public void cartAllDelete(String MEMBER_ID) throws Exception {
		sql.delete(namespace + ".cartAllDelete", MEMBER_ID);	
	}
	
	@Override
	// 二쇰Ц 紐⑸줉
	public List<ShopOrderVO> orderList(ShopOrderVO order) throws Exception {
		return sql.selectList(namespace + ".orderList", order);
	}
	
	// �굹�쓽 二쇰Ц 紐⑸줉
	@Override
	public List<ShopOrderVO> myorderList(ShopOrderVO order) throws Exception {
		return sql.selectList(namespace + ".orderList", order);
	}
	
	
	@Override
	// �듅�젙 二쇰Ц 紐⑸줉
	public List<OrderListVO> orderView(ShopOrderVO order) throws Exception {
		return sql.selectList(namespace + ".orderView", order);
	}


	@Override
	public int addJjim(JjimListVO jjim) throws Exception {
		return (Integer)sql.insert(namespace + ".addJjim", jjim);
	}


	@Override
	public List<JjimListVO> jjimList(String MEMBER_ID) throws Exception {
		return sql.selectList(namespace + ".jjimList", MEMBER_ID);
	}


	@Override
	public void deleteJjim(JjimVO jjim) throws Exception {
		sql.delete(namespace + ".deleteJjim", jjim);
	}


	@Override
	public void jjimAllDelete(String MEMBER_ID) throws Exception {
		sql.delete(namespace + ".jjimAllDelete", MEMBER_ID);
	}


	@Override
	public int findJjim(JjimListVO jjim) throws Exception {
		return (Integer)sql.selectOne(namespace + ".findJjim", jjim);
		
	}
	
	@Override
	public List<GoodsVO> newGoods() throws Exception {
		return sql.selectList(namespace + ".newGoods");
	}

	@Override
	public List<GoodsVO> bestGoods() throws Exception {
		return sql.selectList(namespace + ".bestGoods");
	}
}
