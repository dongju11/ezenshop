package com.ezen.Controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


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

import com.ezen.Other.PageMaker;
import com.ezen.Other.SearchCriteria;
import com.ezen.Service.CommentService;
import com.ezen.Service.boardService;
import com.ezen.Vo.CommentVO;
import com.ezen.Vo.boardVO;

@Controller
@RequestMapping("/board/*")
public class boardController {

private static final Logger logger = LoggerFactory.getLogger(boardController.class);	
	
	@Inject
	boardService service;
	
	@Inject
	CommentService comService;
	
	
	//글작성
	@RequestMapping(value = "/boardWrite", method = RequestMethod.GET)
	public void getboardWrite(HttpSession session, Model model) throws Exception {
		logger.info("get write");
		
		//세션
		Object loginInfo = session.getAttribute("member");
		if(loginInfo == null) {
			model.addAttribute("msg", false);
		}
	}
	
	@RequestMapping(value = "/boardWrite", method = RequestMethod.POST)
	public String postboardWrite(boardVO vo, MultipartHttpServletRequest mpRequest) throws Exception {
	 logger.info("post write");
	 
	 System.out.println(vo.getFr_title());
	 service.write(vo, mpRequest);
	 
	 return "redirect:/board/boardList";
		}	
	
	//상세보기
	@RequestMapping(value = "/boardDetail", method = RequestMethod.GET)
	public void boardView(@RequestParam("fr_no") int fr_no, @ModelAttribute("scri") SearchCriteria scri, Model model) throws Exception {
		logger.info("get read");
		
		boardVO vo = service.read(fr_no);
		model.addAttribute("read", vo);  //뷰에서 read 가져다 씀
		model.addAttribute("scri", scri);
		
		List<CommentVO> comList = comService.comment(fr_no);
		model.addAttribute("comList", comList);
		
		List<Map<String, Object>> fileList = service.selectFileList(fr_no);
		model.addAttribute("file", fileList);
	
	}
	
	// 글 수 정
	@RequestMapping(value = "/boardModify", method = RequestMethod.GET)
	public void getboardModify(@RequestParam("fr_no") int fr_no, @ModelAttribute("scri") SearchCriteria scri, Model model) throws Exception {
	 logger.info("get modify");
	 	 
	 boardVO vo = service.read(fr_no);
	  
	 model.addAttribute("modify", vo);
	 model.addAttribute("scri", scri);
	 
	 List<Map<String, Object>> fileList = service.selectFileList(fr_no);
	 model.addAttribute("file", fileList);
	 
	} 
	
	// 글 수정  POST 
	@RequestMapping(value = "/boardModify", method = RequestMethod.POST)
	public String postboardModify(boardVO vo, @ModelAttribute("scri") SearchCriteria scri, RedirectAttributes rttr,
								@RequestParam(value="fileNoDel[]") String[] files, @RequestParam(value="fileNameDel[]") String[] fileNames, MultipartHttpServletRequest mpRequest) throws Exception {
	 logger.info("post modify");
	 
	 service.update(vo, files, fileNames, mpRequest);
	 
	 rttr.addAttribute("page", scri.getPage());
	 rttr.addAttribute("perPageNum", scri.getPerPageNum());
	 rttr.addAttribute("searchType", scri.getSearchType());
	 rttr.addAttribute("keyword", scri.getKeyword());
	 
	 return "redirect:/board/boardList";
	 
	}
	
	// 글 삭제
	@RequestMapping(value = "/boardRemove", method = RequestMethod.GET)
	public void getboardRemove(@RequestParam("fr_no") int fr_no, @ModelAttribute("scri") SearchCriteria scri, Model model) throws Exception {
	 logger.info("get delete");
	   
	 model.addAttribute("delete", fr_no);
	 model.addAttribute("scri", scri);
	 
	}
	//글 삭제  POST
	@RequestMapping(value = "/boardRemove", method = RequestMethod.POST)
	public String postboardRemove(boardVO vo, @RequestParam("fr_no") int fr_no, @ModelAttribute("scri") SearchCriteria scri, RedirectAttributes rttr) throws Exception {
		logger.info("post delete");
		 
		service.delete(vo.getFr_no());
		
		rttr.addAttribute("page", scri.getPage());
		rttr.addAttribute("perPageNum", scri.getPerPageNum());
		rttr.addAttribute("searchType", scri.getSearchType());
		rttr.addAttribute("keyword", scri.getKeyword());
	
	return "redirect:/board/boardList";
	}
	
	
	//글 목록 + 페이징 + 검색
	@RequestMapping(value = "/boardList", method = RequestMethod.GET)
	public void listPage(@ModelAttribute("scri") SearchCriteria scri, Model model) throws Exception {
	 logger.info("get list search");
	 
	 List<boardVO> list = service.listSearch(scri);
	 model.addAttribute("list", list);
	 
	 PageMaker pageMaker = new PageMaker();
	 pageMaker.setCri(scri);
	 pageMaker.setTotalCount(service.countSearch(scri));
	 model.addAttribute("pageMaker", pageMaker);
	}
	
	
	// 댓글 작성
	@RequestMapping(value = "/commentWrite", method = RequestMethod.POST)
	public String commentWrite(CommentVO vo, SearchCriteria scri, RedirectAttributes rttr) throws Exception {
	 logger.info("comment write");
	 
	 comService.commentWrite(vo);;
	 
	 rttr.addAttribute("fr_no", vo.getFr_no());
	 rttr.addAttribute("page", scri.getPage());
	 rttr.addAttribute("perPageNum", scri.getPerPageNum());
	 rttr.addAttribute("searchType", scri.getSearchType());
	 rttr.addAttribute("keyword", scri.getKeyword());
	 
	 return "redirect:/board/boardDetail"; 
	}
	
	// 댓글 수정 GET
	@RequestMapping(value = "/commentModify", method = RequestMethod.GET)
	public void getReplyUpdate(@RequestParam("comments_no") int comments_no,
	      @ModelAttribute("scri") SearchCriteria scri, Model model) throws Exception {
	 logger.info("comment update");
	 
	 CommentVO vo = null;
	 
	 vo = comService.readComment(comments_no);
	 
	 model.addAttribute("readComment", vo);
	 model.addAttribute("scri", scri);
	}
	
	
	// 댓글 수정 POST
	@RequestMapping(value = "/commentModify", method = RequestMethod.POST)
	public String commentModify(CommentVO vo, SearchCriteria scri, RedirectAttributes rttr) throws Exception {
	 logger.info("comment update");
	 
	 comService.commentModify(vo);;
	 
	 rttr.addAttribute("fr_no", vo.getFr_no());
	 rttr.addAttribute("page", scri.getPage());
	 rttr.addAttribute("perPageNum", scri.getPerPageNum());
	 rttr.addAttribute("searchType", scri.getSearchType());
	 rttr.addAttribute("keyword", scri.getKeyword());
	 
	 return "redirect:/board/boardDetail";
	}

	// 댓글 삭제 GET
	@RequestMapping(value = "/commentDelete", method = RequestMethod.GET)
	public void getReplyDelete(@RequestParam("comments_no") int comments_no,
	      @ModelAttribute("scri") SearchCriteria scri, Model model) throws Exception {
	 logger.info("comment delete");
	 
	 CommentVO vo = null;
	 
	 vo = comService.readComment(comments_no);
	 
	 model.addAttribute("readComment", vo);
	 model.addAttribute("scri", scri);
	}
	
	// 댓글 삭제 POST
	@RequestMapping(value = "/commentDelete", method = RequestMethod.POST)
	public String commentDelete(CommentVO vo, SearchCriteria scri, RedirectAttributes rttr) throws Exception {
	 logger.info("comment delete");
	 
	 comService.commentDelete(vo);
	 
	 rttr.addAttribute("fr_no", vo.getFr_no());
	 rttr.addAttribute("page", scri.getPage());
	 rttr.addAttribute("perPageNum", scri.getPerPageNum());
	 rttr.addAttribute("searchType", scri.getSearchType());
	 rttr.addAttribute("keyword", scri.getKeyword());
	 
	 return "redirect:/board/boardDetail";
	}
	
	//파일 다운
	@RequestMapping(value="/fileDown")
	public void fileDown(@RequestParam Map<String, Object> map, HttpServletResponse response) throws Exception{
		Map<String, Object> resultMap = service.selectFileInfo(map);
		String storedFileName = (String) resultMap.get("NEWFILE_NAME");
		String originalFileName = (String) resultMap.get("ORGFILE_NAME");
	
		
		// 파일을 저장했던 위치에서 첨부파일을 읽어 byte[]형식으로 변환한다.
		byte fileByte[] = org.apache.commons.io.FileUtils.readFileToByteArray(new File("C:\\mp\\file\\"+storedFileName));
		
		response.setContentType("application/octet-stream");
		response.setContentLength(fileByte.length);
		response.setHeader("Content-Disposition",  "attachment; fileName=\""+URLEncoder.encode(originalFileName, "UTF-8")+"\";");
		response.getOutputStream().write(fileByte);
		response.getOutputStream().flush();
		response.getOutputStream().close();
	
	}
}
		
