package com.ezen.Controller;

import java.io.File;
import java.net.URLEncoder;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

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
import com.ezen.Service.boardService;
import com.ezen.Service.reportService;
import com.ezen.Service.qnaService;
import com.ezen.Service.ASService;
import com.ezen.Service.myWroteListService;
import com.ezen.Vo.ASVO;
import com.ezen.Vo.boardVO;
import com.ezen.Vo.qnaVO;
import com.ezen.Vo.reportVO;

@Controller
@RequestMapping("/member/*")
public class myWroteListController {

	@Inject
	myWroteListService service;
	
	@Inject
	boardService boardService;
	
	@Inject
	reportService reportService;
	
	@Inject
	qnaService qnaService;
	
	@Inject
	ASService ASService;
	
	//�궡 �옉�꽦�궡�슜 由ъ뒪�듃+�럹�씠吏�(�옄�쑀寃뚯떆�뙋)
	@RequestMapping(value = "/myWroteList", method = RequestMethod.GET)
	public void myFreeWroteList(@ModelAttribute("cri") Criteria cri, HttpSession session, Model model) throws Exception {
		
		Object loginInfo = session.getAttribute("member");
		
		if(loginInfo == null) {
			model.addAttribute("msg", "login_error");
		}
		
		List<boardVO> freeList = service.freeWroteList(cri);
		model.addAttribute("freeList", freeList);
		
		PageMaker pageMaker1 = new PageMaker();
		pageMaker1.setCri(cri);
		pageMaker1.setTotalCount(service.freeListCount());
		model.addAttribute("pageMaker1", pageMaker1);
		
	}
	//�궡 �옉�꽦�궡�슜 由ъ뒪�듃+�럹�씠吏�(�떊怨좉쾶�떆�뙋)
	@RequestMapping(value = "/myReportWroteList", method = RequestMethod.GET)
	public void myReportWroteList(@ModelAttribute("cri") Criteria cri, HttpSession session, Model model) throws Exception {
		
		Object loginInfo = session.getAttribute("member");
		
		if(loginInfo == null) {
			model.addAttribute("msg", "login_error");
		}
		
		List<reportVO> reportList = service.reportWroteList(cri);
		model.addAttribute("reportList", reportList);
	
		
		PageMaker pageMaker2 = new PageMaker();
		pageMaker2.setCri(cri);
		pageMaker2.setTotalCount(service.reportListCount());
		model.addAttribute("pageMaker2", pageMaker2);
	}
	
	//�궡 �옉�꽦�궡�슜 由ъ뒪�듃+�럹�씠吏�(臾몄쓽寃뚯떆�뙋)
	@RequestMapping(value = "/myQnaWroteList", method = RequestMethod.GET)
	public void myQnaWroteList(@ModelAttribute("cri") Criteria cri, HttpSession session, Model model) throws Exception {
		
		Object loginInfo = session.getAttribute("member");
		
		if(loginInfo == null) {
			model.addAttribute("msg", "login_error");
		}
		
		List<qnaVO> qnaList = service.qnaWroteList(cri);
		model.addAttribute("qnaList", qnaList);
		
		PageMaker pageMaker3 = new PageMaker();
		pageMaker3.setCri(cri);
		pageMaker3.setTotalCount(service.qnaListCount());
		model.addAttribute("pageMaker3", pageMaker3);
	}
		//내가 작성한 환불게시판 글 목록보기
	 @RequestMapping(value ="/myASWroteList", method = RequestMethod.GET)
	 public void myASWrotelist(@ModelAttribute("cri") Criteria cri, HttpSession session, Model model) throws Exception{
		 Object loginInfo = session.getAttribute("member");
			
			if(loginInfo == null) {
				model.addAttribute("msg", "login_error");
			}
			
		 List<ASVO> myASList = service.ASWroteList(cri);
		 
		 model.addAttribute("myASList", myASList);
		 //페이징
		 PageMaker pageMaker4 = new PageMaker();
		 pageMaker4.setCri(cri);
		 pageMaker4.setTotalCount(service.ASListCount());
		 model.addAttribute("pageMaker4", pageMaker4);
	 }
	
	//---------------------------------�옄�쑀 寃뚯떆�뙋�긽�꽭蹂닿린------------------------------------
		@RequestMapping(value = "/myFreeView", method = RequestMethod.GET)
		public void myFreeView(@RequestParam("fr_no") int fr_no, Model model) throws Exception {
			
			boardVO vo = boardService.read(fr_no);
			model.addAttribute("boardRead", vo);  //酉곗뿉�꽌 read 媛��졇�떎 ��
			
			List<Map<String, Object>> fileList = boardService.selectFileList(fr_no);
			model.addAttribute("file", fileList);
		}
		
			// 湲� �닔 �젙
		@RequestMapping(value = "/myFreeModify", method = RequestMethod.GET)
		public void getmyFreeModify(@RequestParam("fr_no") int fr_no, Model model) throws Exception {
		 	 
		 boardVO vo = boardService.read(fr_no);
		  
		 model.addAttribute("modify", vo);
		 
		 List<Map<String, Object>> fileList = boardService.selectFileList(fr_no);
		 model.addAttribute("file", fileList);
		 
		} 
		
		// 湲� �닔�젙  POST 
		@RequestMapping(value = "/myFreeModify", method = RequestMethod.POST)
		public String postmyFreeModify(boardVO vo, RedirectAttributes rttr,
									@RequestParam(value="fileNoDel[]") String[] files, @RequestParam(value="fileNameDel[]") String[] fileNames, MultipartHttpServletRequest mpRequest) throws Exception {
		 
			boardService.update(vo, files, fileNames, mpRequest);
		 
		 return "redirect:/member/myWroteList";
		 
		}
		
		// 湲� �궘�젣
		@RequestMapping(value = "/myFreeRemove", method = RequestMethod.GET)
		public void getmyFreeRemove(@RequestParam("fr_no") int fr_no, Model model) throws Exception {
		   
		 model.addAttribute("delete", fr_no);
		 
		}
		//湲� �궘�젣  POST
		@RequestMapping(value = "/myFreeRemove", method = RequestMethod.POST)
		public String postmyFreeRemove(boardVO vo, @RequestParam("fr_no") int fr_no, RedirectAttributes rttr) throws Exception {
			 
			boardService.delete(vo.getFr_no());
			
		return "redirect:/member/myWroteList";
		}
	
		//--------------------------------�떊怨좉쾶�떆�뙋 �긽�꽭蹂닿린------------------------------------
		@RequestMapping(value = "/myReportView", method = RequestMethod.GET)
		public void myReportView(@RequestParam("report_no") int report_no, Model model) throws Exception {
			
			reportVO vo = reportService.read(report_no);
			model.addAttribute("boardRead", vo);  //酉곗뿉�꽌 read 媛��졇�떎 ��
			
			List<Map<String, Object>> fileList = reportService.selectFileList(report_no);
			model.addAttribute("file", fileList);
		}
		
		// 湲� �닔 �젙
		@RequestMapping(value = "/myReportModify", method = RequestMethod.GET)
		public void getmyReportModify(@RequestParam("report_no") int report_no, Model model) throws Exception {
		 	 
			reportVO vo = reportService.read(report_no);
		  
		 model.addAttribute("modify", vo);
		 
		 List<Map<String, Object>> fileList = reportService.selectFileList(report_no);
		 model.addAttribute("file", fileList);
		 
		} 
		
		// 湲� �닔�젙  POST 
		@RequestMapping(value = "/myReportModify", method = RequestMethod.POST)
		public String postmyReportModify(reportVO vo, RedirectAttributes rttr,
									@RequestParam(value="fileNoDel[]") String[] files, @RequestParam(value="fileNameDel[]") String[] fileNames, MultipartHttpServletRequest mpRequest) throws Exception {
		 
			reportService.update(vo, files, fileNames, mpRequest);
		 
			return "redirect:/member/myWroteList";
		 
		}
		
		// 湲� �궘�젣
		@RequestMapping(value = "/myReportRemove", method = RequestMethod.GET)
		public void getmyReportRemove(@RequestParam("report_no") int report_no, Model model) throws Exception {
		   
		 model.addAttribute("delete", report_no);
		 
		}
		//湲� �궘�젣  POST
		@RequestMapping(value = "/myReportRemove", method = RequestMethod.POST)
		public String postmyReportRemove(reportVO vo, @RequestParam("report_no") int fr_no, RedirectAttributes rttr) throws Exception {
			 
			reportService.delete(vo.getReport_no());
			
			return "redirect:/member/myWroteList";
		}
		
		//--------------------------------臾몄쓽寃뚯떆�뙋 �긽�꽭蹂닿린------------------------------------
		@RequestMapping(value = "/myQnaView", method = RequestMethod.GET)
		public void myQnaView(@RequestParam("qna_no") int qna_no, Model model) throws Exception {
			
			qnaVO vo = qnaService.read(qna_no);
			model.addAttribute("boardRead", vo);  //酉곗뿉�꽌 read 媛��졇�떎 ��
			
			List<Map<String, Object>> fileList = qnaService.selectFileList(qna_no);
			model.addAttribute("file", fileList);
		}
		
	// 湲� �닔 �젙
		@RequestMapping(value = "/myQnaModify", method = RequestMethod.GET)
		public void getmyQnaModify(@RequestParam("qna_no") int qna_no, Model model) throws Exception {
		 	 
			qnaVO vo = qnaService.read(qna_no);
		  
		 model.addAttribute("modify", vo);
		 
		 List<Map<String, Object>> fileList = qnaService.selectFileList(qna_no);
		 model.addAttribute("file", fileList);
		 
		} 
		
		// 湲� �닔�젙  POST 
		@RequestMapping(value = "/myQnaModify", method = RequestMethod.POST)
		public String postmyQnaModify(qnaVO vo, RedirectAttributes rttr,
									@RequestParam(value="fileNoDel[]") String[] files, @RequestParam(value="fileNameDel[]") String[] fileNames, MultipartHttpServletRequest mpRequest) throws Exception {
		 
			qnaService.update(vo, files, fileNames, mpRequest);
		 
		return "redirect:/member/myWroteList";
		 
		}
		
		// 湲� �궘�젣
		@RequestMapping(value = "/myQnaRemove", method = RequestMethod.GET)
		public void getmyQnaRemove(@RequestParam("qna_no") int qna_no, Model model) throws Exception {
		   
		 model.addAttribute("delete", qna_no);
		 
		}
		//湲� �궘�젣  POST
		@RequestMapping(value = "/myQnaRemove", method = RequestMethod.POST)
		public String postmyQnaRemove(qnaVO vo, @RequestParam("qna_no") int qna_no, RedirectAttributes rttr) throws Exception {
			 
			qnaService.delete(vo.getQna_no());
			
		return "redirect:/member/myWroteList";
		}
		
		
		//�뙆�씪 �떎�슫
		@RequestMapping(value="/fileDown")
		public void fileDown(@RequestParam Map<String, Object> map, HttpServletResponse response) throws Exception{
			Map<String, Object> resultMap = service.selectFileInfo(map);
			String storedFileName = (String) resultMap.get("NEWFILE_NAME");
			String originalFileName = (String) resultMap.get("ORGFILE_NAME");
		
			
			// �뙆�씪�쓣 ���옣�뻽�뜕 �쐞移섏뿉�꽌 泥⑤��뙆�씪�쓣 �씫�뼱 byte[]�삎�떇�쑝濡� 蹂��솚�븳�떎.
			byte fileByte[] = org.apache.commons.io.FileUtils.readFileToByteArray(new File("C:\\mp\\file\\"+storedFileName));
			
			response.setContentType("application/octet-stream");
			response.setContentLength(fileByte.length);
			response.setHeader("Content-Disposition",  "attachment; fileName=\""+URLEncoder.encode(originalFileName, "UTF-8")+"\";");
			response.setHeader("Content-Transfer-Encoding", "binary");
			response.getOutputStream().write(fileByte);
			response.getOutputStream().flush();
			response.getOutputStream().close();
		
		}
		//--------------------------------환불게시판------------------------------------
	

		 // 내가 작성한 환불게시판 글 상세보기
		 @RequestMapping(value ="/myASView", method =RequestMethod.GET)
		 public void asgetRead(@RequestParam("as_no") int as_no, Model model) throws Exception{
			 
			 ASVO vo = ASService.read(as_no);
			 
			 model.addAttribute("read", vo);
		 }
		 
		// 환불게시판 글 수정
		@RequestMapping(value = "/myASModify", method = RequestMethod.GET)
		public void asgetModify(@RequestParam("as_no") int as_no, Model model) throws Exception {

			ASVO vo = ASService.read(as_no);

			model.addAttribute("modify", vo);

		} 

		@RequestMapping(value = "/myASModify", method = RequestMethod.POST)
		public String aspostModify(ASVO vo) throws Exception {

		ASService.update(vo);

		return "redirect:./myASWroteList";

		}

		// 환불게시판 글 삭제
		@RequestMapping(value = "/myASRemove", method = RequestMethod.GET)
		public void asgetDelete(@RequestParam("as_no") int as_no, Model model) throws Exception {
		  
			model.addAttribute("delete", as_no);

		}
		 
		@RequestMapping(value = "/myASRemove", method = RequestMethod.POST)
		public String aspostDelete(@RequestParam("as_no") int as_no) throws Exception {
		   
		 ASService.delete(as_no);
		 
		 return "redirect:./myASWroteList";
		}


}
