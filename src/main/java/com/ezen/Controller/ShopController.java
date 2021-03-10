package com.ezen.Controller;


import java.text.DecimalFormat;
import java.util.Calendar;
import java.util.List;

import javax.inject.Inject;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.ezen.Service.ShopService;
import com.ezen.Vo.CartListVO;
import com.ezen.Vo.CartVO;
import com.ezen.Vo.GoodsDetailVO;
import com.ezen.Vo.GoodsVO;
import com.ezen.Vo.JjimListVO;
import com.ezen.Vo.JjimVO;
import com.ezen.Vo.MemberVO;
import com.ezen.Vo.OrderListVO;
import com.ezen.Vo.ShopOrderDetailVO;
import com.ezen.Vo.ShopOrderVO;
import com.ezen.Vo.ShopReplyListVO;
import com.ezen.Vo.ShopReplyVO;


@Controller
@RequestMapping("/shop/*")
public class ShopController {
	
	private static final Logger logger = LoggerFactory.getLogger(ShopController.class);
	
	@Inject
	ShopService service;
	
	@RequestMapping(value = "/shopmain")
	public String shopmain() throws Exception{
		
		return "/shop/shopmain";
	}
	
	@RequestMapping(value = "/list", method = RequestMethod.GET)
	public void getLIST(@RequestParam("c") int GOODS_CATEGORY,
						@RequestParam("l") int level, Model model) throws Exception{
		
		List<GoodsDetailVO> list = null;
		list = service.list(GOODS_CATEGORY, level);
		model.addAttribute("list", list);
		 
	} 
	
	// 占쎄맒占쎈�� 鈺곌퀬�돳
	@RequestMapping(value = "/view", method = RequestMethod.GET)
	public void getView(@RequestParam("n") int GOODS_NO, Model model) throws Exception{
		
		GoodsDetailVO view = service.goodsdetail(GOODS_NO);
		model.addAttribute("view", view);
		
		List<ShopReplyListVO> reply = service.replyList(GOODS_NO);
		model.addAttribute("reply", reply);
		
		
	}
	
	
	//占쎄맒占쎈�� 占쎈솊疫뀐옙 占쎌삂占쎄쉐
	@RequestMapping(value = "/view", method = RequestMethod.POST)
	public String registReply(ShopReplyVO reply, HttpSession session) throws Exception {
		
		logger.info("占쎈쑅筌욑옙疫뀀똾釉�占쎄튂");
		
		MemberVO member = (MemberVO)session.getAttribute("member");
		reply.setMEMBER_ID(member.getMEMBER_ID());
		
		service.registReply(reply);
		
		return "redirect:/shop/view?n=" + reply.getGOODS_NO();
	}
	
	@ResponseBody
	@RequestMapping(value = "/view/addJjim", method = RequestMethod.POST)
	public boolean addJjim(JjimListVO jjim, HttpSession session) throws Exception {
		
		logger.info("찜추가");
		
		MemberVO member = (MemberVO)session.getAttribute("member");
		
		if(member != null) {
		jjim.setMEMBER_ID(member.getMEMBER_ID());
		}
		
		int result = service.addJjim(jjim);
		
		if(result>0) {
			return true;
		}
		return false;
	}

	@RequestMapping(value = "/jjimList", method = RequestMethod.GET)
	public void getJjimList(HttpSession session, Model model) throws Exception {
		
		logger.info("찜리스트");
		
		MemberVO member = (MemberVO)session.getAttribute("member");
		String MEMBER_ID = member.getMEMBER_ID();
		
		List<JjimListVO> jjimList = service.jjimList(MEMBER_ID);
		
		model.addAttribute("jjimList", jjimList);
	}
	
	
	@ResponseBody
	@RequestMapping(value = "/deleteJjim", method = RequestMethod.POST)
	public int deleteJjim(HttpSession session,
				@RequestParam(value = "chbox[]") List<String> chArr, JjimVO jjim) throws Exception {
		
		logger.info("찜삭제");
		
		MemberVO member = (MemberVO)session.getAttribute("member");
		String MEMBER_ID = member.getMEMBER_ID();
		
		int result = 0;
		int JJIM_NUM = 0;
		
		if(member != null) {
			jjim.setMEMBER_ID(MEMBER_ID);
			
			for(String i : chArr) {
				JJIM_NUM = Integer.parseInt(i);
				jjim.setJJIM_NUM(JJIM_NUM);;
				service.deleteJjim(jjim);;
			}
			result = 1;
		}
			
		return result;
	}

	@RequestMapping(value = "/jjimList", method = RequestMethod.POST)
	public String order(HttpSession session) throws Exception {
		logger.info("찜리스트");
		
		MemberVO member = (MemberVO)session.getAttribute("member");
		String MEMBER_ID = member.getMEMBER_ID();
		
		service.cartAllDelete(MEMBER_ID);
		
		return "redirect:/shop/jjimList";
	}
	
	// 燁삳똾�뱜 占쎈뼖疫뀐옙
	@ResponseBody
	@RequestMapping(value = "/view/addCart", method = RequestMethod.POST)
	public int addCart(CartListVO cart, HttpSession session) throws Exception {
		
		logger.info("占쎈툧占쎄퐜占쎈선占쎌궎占쎄튂!!!!");
		
		int result = 0;
		
		MemberVO member = (MemberVO)session.getAttribute("member");
		
		if(member != null) {
		cart.setMEMBER_ID(member.getMEMBER_ID());
		service.addCart(cart);
		result = 1;
		}
		return result;
	}
	
	// 占쎌삢獄쏅떽�럡占쎈빍 筌뤴뫖以�
	@RequestMapping(value = "/cartList", method = RequestMethod.GET)
	public void getCartList(HttpSession session, Model model) throws Exception {
		
		logger.info("占쎈툧占쎄퐜占쎈선占쎌궎占쎄튂!!");
		
		MemberVO member = (MemberVO)session.getAttribute("member");
		String MEMBER_ID = member.getMEMBER_ID();
		
		List<CartListVO> cartList = service.cartList(MEMBER_ID);
		
		model.addAttribute("cartList", cartList);
	}
	
	//燁삳똾�뱜 占쎄텣占쎌젫
	@ResponseBody
	@RequestMapping(value = "/deleteCart", method = RequestMethod.POST)
	public int deleteCart(HttpSession session,
				@RequestParam(value = "chbox[]") List<String> chArr, CartVO cart) throws Exception {
		
		logger.info("燁삳똾�뱜占쎄텣占쎌젫");
		
		MemberVO member = (MemberVO)session.getAttribute("member");
		String MEMBER_ID = member.getMEMBER_ID();
		
		int result = 0;
		int CART_NO = 0;
		
		if(member != null) {
			cart.setMEMBER_ID(MEMBER_ID);
			
			for(String i : chArr) {
				CART_NO = Integer.parseInt(i);
				cart.setCART_NO(CART_NO);
				service.deleteCart(cart);
			}
			result = 1;
		}
			
		return result;
	}
	
	// 雅뚯눖揆
	@RequestMapping(value = "cartList", method = RequestMethod.POST)
	public String order(HttpSession session, ShopOrderVO order, ShopOrderDetailVO shopOrderDetail) throws Exception {
		logger.info("雅뚯눖揆占쎄퐜占쎈선占쎌궎占쎄튂?");
		
		MemberVO member = (MemberVO)session.getAttribute("member");
		String MEMBER_ID = member.getMEMBER_ID();
		
		Calendar cal = Calendar.getInstance();
		int year = cal.get(Calendar.YEAR);
		String ym = year + new DecimalFormat("00").format(cal.get(Calendar.MONTH) + 1);
		String ymd = ym +  new DecimalFormat("00").format(cal.get(Calendar.DATE));
		String subNum = "";
		 
		for(int i = 1; i <= 6; i ++) {
		  subNum += (int)(Math.random() * 10);
		}
		
		String ORDER_ID = ymd + "_" + subNum;
		
		order.setORDER_ID(ORDER_ID);
		order.setMEMBER_ID(MEMBER_ID);
		
		service.orderInfo(order);
		
		shopOrderDetail.setORDER_ID(ORDER_ID);
		service.orderInfo_Details(shopOrderDetail);
		
		service.cartAllDelete(MEMBER_ID);
		
		return "redirect:/shop/orderList";
	}
	
	// 雅뚯눖揆 筌뤴뫖以�
	@RequestMapping(value = "/orderList", method = RequestMethod.GET)
	public void getOrderList(HttpSession session, ShopOrderVO order, Model model) throws Exception {
		
		MemberVO member = (MemberVO)session.getAttribute("member");
		String MEMBER_ID = member.getMEMBER_ID();
		
		order.setMEMBER_ID(MEMBER_ID);
				
		List<ShopOrderVO> orderList = service.orderList(order);
		
		model.addAttribute("orderList", orderList);
		
	}
	
	// 占쎄땀 雅뚯눖揆 筌뤴뫖以�
	@RequestMapping(value = "/myorderList", method = RequestMethod.GET)
	public void getmyOrderList(HttpSession session, ShopOrderVO order, Model model) throws Exception {
		
		MemberVO member = (MemberVO)session.getAttribute("member");
		String MEMBER_ID = member.getMEMBER_ID();
		
		order.setMEMBER_ID(MEMBER_ID);
				
		List<ShopOrderVO> myorderList = service.orderList(order);
		
		model.addAttribute("myorderList", myorderList);
		
	}
	
	
	// 雅뚯눖揆 占쎄맒占쎄쉭 筌뤴뫖以�
	@RequestMapping(value = "/orderView", method = RequestMethod.GET)
	public void getOrderList(HttpSession session,
							@RequestParam("n") String orderId, ShopOrderVO order, Model model) throws Exception {
		
		logger.info("雅뚯눖揆 占쎄맒占쎄쉭 筌뤴뫖以�");
		
		MemberVO member = (MemberVO)session.getAttribute("member");
		String MEMBER_ID = member.getMEMBER_ID();
		
		order.setMEMBER_ID(MEMBER_ID);
		order.setORDER_ID(orderId);
		
		List<OrderListVO> orderView = service.orderView(order);
		
		model.addAttribute("orderView", orderView);
		
	}
	
	@RequestMapping(value = "/newGoods", method = RequestMethod.GET)
	public void getNewGoods(Model model) throws Exception{
			
		List<GoodsVO> list = service.newGoods();
		
		model.addAttribute("newGoods", list);
		 
	} 
	
	@RequestMapping(value = "/bestGoods", method = RequestMethod.GET)
	public void getBestGoods(Model model) throws Exception{
			
		List<GoodsVO> list = service.bestGoods();
		
		model.addAttribute("bestGoods", list);
	}
	
}