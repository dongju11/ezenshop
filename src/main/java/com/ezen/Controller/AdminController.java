package com.ezen.Controller;

import java.io.File;
import java.net.URLEncoder;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartHttpServletRequest;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.ezen.Other.Criteria;
import com.ezen.Other.PageMaker;
import com.ezen.Other.SearchCriteria;
import com.ezen.Service.boardService;
import com.ezen.Service.qnaService;
import com.ezen.Service.reportService;
import com.ezen.Vo.ASVO;
import com.ezen.Vo.CommentVO;
import com.ezen.Vo.GoodsDetailVO;
import com.ezen.Vo.GoodsVO;
import com.ezen.Vo.MemberVO;
import com.ezen.Vo.NoticeVO;
import com.ezen.Vo.OrderListVO;
import com.ezen.Vo.ReplyVO;
import com.ezen.Vo.ShopOrderVO;
import com.ezen.Vo.ShopReplyListVO;
import com.ezen.Vo.boardVO;
import com.ezen.Vo.qnaVO;
import com.ezen.Vo.reportVO;
import com.ezen.Service.ASService;
import com.ezen.Service.AdminService;
import com.ezen.Service.CommentService;
import com.ezen.Service.MemberService;
import com.ezen.Service.NoticeService;
import com.ezen.Service.ReplyService;


@Controller
@RequestMapping("/admin/*")
public class AdminController {
	
	@Inject
	AdminService adminService;
	
	@Inject
	boardService service1;
	
	@Inject
	qnaService service2;
	
	@Inject
	reportService service3;
	
	@Inject //공지사항
	NoticeService service;
	
	@Inject // 댓글
	CommentService comService;
	
	@Inject // 교환 환불
	ASService service4;
	
	
	@Inject //회원
	MemberService memberservice;
	
		
	private static final Logger logger = LoggerFactory.getLogger(AdminController.class);
	
	@RequestMapping(value = "/adminhome", method = RequestMethod.GET)
	public void getAdminhome() throws Exception {
		logger.info("愿�由ъ옄 �뱾�뼱�솕�깘");
	}

	// �옄�쑀寃뚯떆�뙋 湲� 紐⑸줉 + �럹�씠吏� + 寃��깋
		@RequestMapping(value = "/board/boardList", method = RequestMethod.GET)
		public void listPage(@ModelAttribute("scri") SearchCriteria scri, Model model) throws Exception {
		 logger.info("get list search");
		 
		 List<boardVO> list = service1.listSearch(scri);
		 model.addAttribute("list", list);
		 
		 PageMaker pageMaker = new PageMaker();
		 pageMaker.setCri(scri);
		 pageMaker.setTotalCount(service1.countSearch(scri));
		 model.addAttribute("pageMaker", pageMaker);
		}

		//臾몄쓽寃뚯떆�뙋 湲� 紐⑸줉 + �럹�씠吏� + 寃��깋
		 @RequestMapping(value = "/board/QnaList", method = RequestMethod.GET)
		 public void qnaList(@ModelAttribute("scri") SearchCriteria scri, Model model) throws Exception {
			 logger.info("get list search");
			 
			 List<qnaVO> list = service2.listSearch(scri);
			 model.addAttribute("list", list);
			 
			 PageMaker pageMaker = new PageMaker();
			 pageMaker.setCri(scri);
			 pageMaker.setTotalCount(service2.countSearch(scri));
			 model.addAttribute("pageMaker", pageMaker);
		 }

		//�떊怨� 寃뚯떆�뙋 湲� 紐⑸줉 + �럹�씠吏� + 寃��깋
			@RequestMapping(value = "/board/reportBoardList", method = RequestMethod.GET)
			public void reportList(@ModelAttribute("scri") SearchCriteria scri, Model model) throws Exception {
			 logger.info("get list search");
			 
			 List<reportVO> list = service3.listSearch(scri);
			 model.addAttribute("list", list);
			 
			 PageMaker pageMaker = new PageMaker();
			 pageMaker.setCri(scri);
			 pageMaker.setTotalCount(service3.countSearch(scri));
			 model.addAttribute("pageMaker", pageMaker);
			}
			
			
		// 二쇰Ц 紐⑸줉
		@RequestMapping(value = "/shop/orderList", method = RequestMethod.GET)
		public void getOrderList(Model model) throws Exception {
			logger.info("二쇰Ц紐⑸줉 遺덈윭�삤湲�");
			
			List<ShopOrderVO> orderList = adminService.orderList();
			
			model.addAttribute("orderList", orderList);
		}
			
		
		// 二쇰Ц �긽�꽭 紐⑸줉
		@RequestMapping(value = "/shop/orderView", method = RequestMethod.GET)
		public void getOrderList(@RequestParam("n") String ORDER_ID,
								ShopOrderVO order, Model model) throws Exception {
			logger.info("二쇰Ц �긽�꽭 紐⑸줉 遺덈윭�삤湲�");
			
			order.setORDER_ID(ORDER_ID);

			List<OrderListVO> orderView = adminService.orderView(order);
			
			model.addAttribute("orderView", orderView);
			
		}
		
		// 二쇰Ц �긽�꽭 紐⑸줉 諛곗넚 �긽�깭 蹂�寃�
		@RequestMapping(value = "/shop/orderView", method = RequestMethod.POST)
		public String delivery(ShopOrderVO order) throws Exception {
			
			logger.info("諛곗넚�긽�깭蹂�寃�");
			
			adminService.delivery(order);
			
			return "redirect:/admin/shop/orderView?n=" + order.getORDER_ID();
		}
			
		// �긽�뭹 紐⑸줉
		@RequestMapping(value = "/goods/goodslist", method = RequestMethod.GET)
		public void getGoodsList(Model model) throws Exception {
			
			List<GoodsDetailVO> list = adminService.goodslist();
			
			model.addAttribute("goodslist", list);
			
		}
		
		// �긽�뭹 議고쉶
		@RequestMapping(value = "/goods/goodsdetail", method = RequestMethod.GET)
		public void getgoodsdetail(@RequestParam("n") int GOODS_NO, Model model) throws Exception{
				
			GoodsDetailVO goods = adminService.goodsdetail(GOODS_NO);
			
			model.addAttribute("goods", goods);
			
			 
		} 
		 //교환 환불게시판 목록보기
		 @RequestMapping(value ="/as/aslist", method = RequestMethod.GET)
		 public void list(@ModelAttribute("cri")Criteria cri, Model model) throws Exception{
			 logger.info("get list");
			 
			 List<ASVO> list = service4.list(cri);
			 
			 model.addAttribute("list", list);
			 //페이징
			 PageMaker pageMaker = new PageMaker();
			 pageMaker.setCri(cri);
			 pageMaker.setTotalCount(service4.listCount());
			 model.addAttribute("pageMaker", pageMaker);
		 }
		 // 교환 환불게시판 글 상세보기
		 @RequestMapping(value ="/as/asdetail", method =RequestMethod.GET)
		 public void getRead(@RequestParam("as_no") int as_no, Model model) throws Exception{
			 logger.info("get Detail");
			 
			 ASVO vo = service4.read(as_no);
			 
			 model.addAttribute("read", vo);
		 }
		 
			// 공지사항 목록보기
		 @RequestMapping(value = "/notice/noticeList", method = RequestMethod.GET)
			public void noticeList(@ModelAttribute("scri") SearchCriteria scri, Model model) throws Exception {
				logger.info("get noticelist search");

				List<NoticeVO> list = service.listSearch(scri);
				model.addAttribute("list", list);

				PageMaker pageMaker = new PageMaker();
				pageMaker.setCri(scri);
				pageMaker.setTotalCount(service.countSearch(scri));
				model.addAttribute("pageMaker", pageMaker);
			}
			
		//공지사항 글 쓰기
		@RequestMapping(value = "/notice/notieWrite", method = RequestMethod.GET)
		public void getWrite() throws Exception {
			logger.info("get admin write");
		}
		
		//공지사항 작성
		@RequestMapping(value = "/notice/noticeWrite", method = RequestMethod.GET)
		public void getWrite(HttpSession session, Model model) throws Exception {
			logger.info("get notice write");
			
			Object loginInfo = session.getAttribute("member");
			if(loginInfo == null) {
				model.addAttribute("msg", false);
			}
		}

		@RequestMapping(value = "/notice/noticeWrite", method = RequestMethod.POST)
		public String postWrite(NoticeVO vo, MultipartHttpServletRequest mpRequest) throws Exception {
			logger.info("post write");

			 System.out.println(vo.getNotice_title());
			 service.write(vo, mpRequest);
			 
			 return "redirect:/admin/notice/noticeList";
		}	
		//공지사항 상세보기 
		@RequestMapping(value = "/notice/noticeDetail", method = RequestMethod.GET)
		public void noticeView(@RequestParam("notice_no") int notice_no, @ModelAttribute("scri") SearchCriteria scri,
				Model model) throws Exception {
			logger.info("get notice read");

			NoticeVO vo = service.read(notice_no);
			model.addAttribute("read", vo);
			model.addAttribute("scri", scri);

			List<CommentVO> comList = comService.noticeComment(notice_no);
			model.addAttribute("comList", comList);
			
			List<Map<String, Object>> fileList = service.selectFileList(notice_no);
			model.addAttribute("file", fileList);
			
		}
		//공지사항 수정
		@RequestMapping(value = "/notice/noticeModify", method = RequestMethod.GET)
		public void getnoticeModify(@RequestParam("notice_no") int notice_no, @ModelAttribute("scri") SearchCriteria scri,
				Model model) throws Exception {

			logger.info("get notice modify");

			NoticeVO vo = service.read(notice_no);

			model.addAttribute("modify", vo);
			model.addAttribute("scri", scri);
			
			 List<Map<String, Object>> fileList = service.selectFileList(notice_no);
			 model.addAttribute("file", fileList);
			 
		}
		
		@RequestMapping(value = "/notice/noticeModify", method = RequestMethod.POST)
		public String postnoticeModify(NoticeVO vo, @ModelAttribute("scri") SearchCriteria scri, RedirectAttributes rttr,
				@RequestParam(value="fileNoDel[]") String[] files, @RequestParam(value="fileNameDel[]") String[] fileNames, MultipartHttpServletRequest mpRequest)
				throws Exception {
			logger.info("post modify");

			service.update(vo, files, fileNames, mpRequest);

			rttr.addAttribute("page", scri.getPage());
			rttr.addAttribute("perPageNum", scri.getPerPageNum());
			rttr.addAttribute("searchType", scri.getSearchType());
			rttr.addAttribute("keyword", scri.getKeyword());

			return "redirect:/admin/notice/noticeList";
		}
		//공지사항 삭제
		@RequestMapping(value = "/notice/noticeRemove", method = RequestMethod.GET)
		public void getnoticeRemove(@RequestParam("notice_no") int notice_no, @ModelAttribute("scri") SearchCriteria scri,
				Model model) throws Exception {
			logger.info("get notice delete");

			model.addAttribute("delete", notice_no);
			model.addAttribute("scri", scri);
		}

		@RequestMapping(value = "/notice/noticeRemove", method = RequestMethod.POST)
		public String postnoticeRemove(NoticeVO vo, @RequestParam("notice_no") int notice_no, @ModelAttribute("scri") SearchCriteria scri,
				RedirectAttributes rttr) throws Exception {
			logger.info("post notice delete");

			service.delete(vo.getNotice_no());

			rttr.addAttribute("page", scri.getPage());
			rttr.addAttribute("perPageNum", scri.getPerPageNum());
			rttr.addAttribute("searchType", scri.getSearchType());
			rttr.addAttribute("keyword", scri.getKeyword());

			return "redirect:/admin/notice/noticeList";
		}
		
		@RequestMapping(value = "/notice/commentWrite", method = RequestMethod.POST)
		public String commentWrite(CommentVO vo, SearchCriteria scri, RedirectAttributes rttr) throws Exception {
			logger.info("comment write");

			comService.commentWrite(vo);

			rttr.addAttribute("notice_no", vo.getNotice_no());
			rttr.addAttribute("page", scri.getPage());
			rttr.addAttribute("perPageNum", scri.getPerPageNum());
			rttr.addAttribute("searchType", scri.getSearchType());
			rttr.addAttribute("keyword", scri.getKeyword());

			return "redirect:/admin/notice/noticeDetail";
		}

		//怨듭��궗�빆 �뙎湲� �닔�젙
		@RequestMapping(value = "/notice/commentModify", method = RequestMethod.GET)
		public void getReplyUpdate(@RequestParam("comments_no") int comments_no,
		      @ModelAttribute("scri") SearchCriteria scri, Model model) throws Exception {
		 logger.info("comment update");
		 
		 CommentVO vo = null;
		 
		 vo = comService.readComment(comments_no);
		 
		 model.addAttribute("readComment", vo);
		 model.addAttribute("scri", scri);
		}
		
		
		@RequestMapping(value = "/notice/commentModify", method = RequestMethod.POST)
		public String commentModify(CommentVO vo, SearchCriteria scri, RedirectAttributes rttr) throws Exception {
			logger.info("comment update");

			comService.commentModify(vo);

			rttr.addAttribute("notice_no", vo.getNotice_no());
			rttr.addAttribute("page", scri.getPage());
			rttr.addAttribute("perPageNum", scri.getPerPageNum());
			rttr.addAttribute("searchType", scri.getSearchType());
			rttr.addAttribute("keyword", scri.getKeyword());

			return "redirect:/admin/notice/noticeDetail";
		}

	// �뙎湲� �궘�젣
		@RequestMapping(value = "/notice/commentDelete", method = RequestMethod.GET)
		public void getReplyDelete(@RequestParam("comments_no") int comments_no,
		      @ModelAttribute("scri") SearchCriteria scri, Model model) throws Exception {
		 logger.info("comment delete");
		 
		 CommentVO vo = null;
		 
		 vo = comService.readComment(comments_no);
		 
		 model.addAttribute("readComment", vo);
		 model.addAttribute("scri", scri);
		}
		
		@RequestMapping(value = "/notice/commentDelete", method = RequestMethod.POST)
		public String commentDelete(CommentVO vo, SearchCriteria scri, RedirectAttributes rttr) throws Exception {
		 logger.info("comment delete");
		 
		 comService.commentDelete(vo);
		 
		 rttr.addAttribute("notice_no", vo.getNotice_no());
		 rttr.addAttribute("page", scri.getPage());
		 rttr.addAttribute("perPageNum", scri.getPerPageNum());
		 rttr.addAttribute("searchType", scri.getSearchType());
		 rttr.addAttribute("keyword", scri.getKeyword());
		 
		 return "redirect:/admin/notice/noticeDetail";
		}
		
		//�뙆�씪 �떎�슫濡쒕뱶
		@RequestMapping(value="/fileDown")
		public void fileDown(@RequestParam Map<String, Object> map, HttpServletResponse response) throws Exception{
			Map<String, Object> resultMap = service.selectFileInfo(map);
			String storedFileName = (String) resultMap.get("NEWFILE_NAME");
			String originalFileName = (String) resultMap.get("ORGFILE_NAME");
		
			
			// 占쎈솁占쎌뵬占쎌뱽 占쏙옙占쎌삢占쎈뻥占쎈쐲 占쎌맄燁살꼷肉됵옙苑� 筌ｂ뫀占쏙옙�솁占쎌뵬占쎌뱽 占쎌뵭占쎈선 byte[]占쎌굨占쎈뻼占쎌몵嚥∽옙 癰귨옙占쎌넎占쎈립占쎈뼄.
			byte fileByte[] = org.apache.commons.io.FileUtils.readFileToByteArray(new File("C:\\mp\\file\\"+storedFileName));
			
			response.setContentType("application/octet-stream");
			response.setContentLength(fileByte.length);
			response.setHeader("Content-Disposition",  "attachment; fileName=\""+URLEncoder.encode(originalFileName, "UTF-8")+"\";");
			response.getOutputStream().write(fileByte);
			response.getOutputStream().flush();
			response.getOutputStream().close();
		
		}
		
		// 상품 목록 + 페이징 + 검색
		@RequestMapping(value = "goods/goodslistSearch", method = RequestMethod.GET)
		public void goodslistSearch(@ModelAttribute("scri") SearchCriteria scri, Model model) throws Exception {
			logger.info("페이이이이지지지ㅣ이잉");
			
			
			
			List<GoodsVO> list = adminService.goodslistSearch(scri);
			
			
			model.addAttribute("list", list);
			
			PageMaker shoppageMaker = new PageMaker();
			shoppageMaker.setCri(scri);
			//pageMaker.setTotalCount(adminService.listCount());
			shoppageMaker.setTotalCount(adminService.countSearch(scri));
			model.addAttribute("pageMaker", shoppageMaker);
			
		}
		
		// 모든 댓글
		@RequestMapping(value = "/shop/allReply", method = RequestMethod.GET)
		public void getAllReply(Model model) throws Exception {
			logger.info("댓글 소환");
			
			List<ShopReplyListVO> reply = adminService.allReply();
			
			model.addAttribute("reply", reply);
		}}
		
	
