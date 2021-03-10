package com.ezen.Controller;

import java.util.List;
import java.util.Map;
import java.net.URLEncoder;

import javax.inject.Inject;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

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
import com.ezen.Service.NoticeService;
import com.ezen.Vo.CommentVO;
import com.ezen.Vo.NoticeVO;

@Controller
@RequestMapping("/notice/*")
public class NoticeController {

	private static final Logger logger = LoggerFactory.getLogger(NoticeController.class);

	@Inject
	NoticeService service;

	@Inject
	CommentService comService;

	//공지사항 작성
	@RequestMapping(value = "/noticeWrite", method = RequestMethod.GET)
	public void getWrite(HttpSession session, Model model) throws Exception {
		logger.info("get notice write");
		
		Object loginInfo = session.getAttribute("member");
		if(loginInfo == null) {
			model.addAttribute("msg", false);
		}
	}

	@RequestMapping(value = "/noticeWrite", method = RequestMethod.POST)
	public String postWrite(NoticeVO vo, MultipartHttpServletRequest mpRequest) throws Exception {
		logger.info("post write");

		 System.out.println(vo.getNotice_title());
		 service.write(vo, mpRequest);
		 
		 return "redirect:/notice/noticeList";
	}	
	//공지사항 상세보기 
	@RequestMapping(value = "/noticeDetail", method = RequestMethod.GET)
	public void noticeView(@RequestParam("notice_no") int notice_no, @ModelAttribute("scri") SearchCriteria scri,
			Model model) throws Exception {
		logger.info("get notice read");

		NoticeVO vo = service.read(notice_no);
		model.addAttribute("read", vo);
		model.addAttribute("scri", scri);
		//댓글
		List<CommentVO> comList = comService.noticeComment(notice_no);
		model.addAttribute("comList", comList);
		//첨부파일 목록
		List<Map<String, Object>> fileList = service.selectFileList(notice_no);
		model.addAttribute("file", fileList);
		
	}
	//공지사항 수정
	@RequestMapping(value = "/noticeModify", method = RequestMethod.GET)
	public void getnoticeModify(@RequestParam("notice_no") int notice_no, @ModelAttribute("scri") SearchCriteria scri,
			Model model) throws Exception {

		logger.info("get notice modify");

		NoticeVO vo = service.read(notice_no);

		model.addAttribute("modify", vo);
		model.addAttribute("scri", scri);
		
		 List<Map<String, Object>> fileList = service.selectFileList(notice_no);
		 model.addAttribute("file", fileList);
		 
	}
	
	@RequestMapping(value = "/noticeModify", method = RequestMethod.POST)
	public String postnoticeModify(NoticeVO vo, @ModelAttribute("scri") SearchCriteria scri, RedirectAttributes rttr,
			@RequestParam(value="fileNoDel[]") String[] files, @RequestParam(value="fileNameDel[]") String[] fileNames, MultipartHttpServletRequest mpRequest)
			throws Exception {
		logger.info("post modify");

		service.update(vo, files, fileNames, mpRequest);

		rttr.addAttribute("page", scri.getPage());
		rttr.addAttribute("perPageNum", scri.getPerPageNum());
		rttr.addAttribute("searchType", scri.getSearchType());
		rttr.addAttribute("keyword", scri.getKeyword());

		return "redirect:/notice/noticeList";
	}
	//공지사항 삭제
	@RequestMapping(value = "/noticeRemove", method = RequestMethod.GET)
	public void getnoticeRemove(@RequestParam("notice_no") int notice_no, @ModelAttribute("scri") SearchCriteria scri,
			Model model) throws Exception {
		logger.info("get notice delete");

		model.addAttribute("delete", notice_no);
		model.addAttribute("scri", scri);
	}

	@RequestMapping(value = "/noticeRemove", method = RequestMethod.POST)
	public String postnoticeRemove(NoticeVO vo, @RequestParam("notice_no") int notice_no, @ModelAttribute("scri") SearchCriteria scri,
			RedirectAttributes rttr) throws Exception {
		logger.info("post notice delete");

		service.delete(vo.getNotice_no());

		rttr.addAttribute("page", scri.getPage());
		rttr.addAttribute("perPageNum", scri.getPerPageNum());
		rttr.addAttribute("searchType", scri.getSearchType());
		rttr.addAttribute("keyword", scri.getKeyword());

		return "redirect:/notice/noticeList";
	}
	//공지사항 목록보기
	@RequestMapping(value = "/noticeList", method = RequestMethod.GET)
	public void noticeList(@ModelAttribute("scri") SearchCriteria scri, Model model) throws Exception {
		logger.info("get noticelist search");

		List<NoticeVO> list = service.listSearch(scri);
		model.addAttribute("list", list);

		PageMaker pageMaker = new PageMaker();
		pageMaker.setCri(scri);
		pageMaker.setTotalCount(service.countSearch(scri));
		model.addAttribute("pageMaker", pageMaker);
	}
	
	//댓글 작성하기
	@RequestMapping(value = "/commentWrite", method = RequestMethod.POST)
	public String commentWrite(CommentVO vo, SearchCriteria scri, RedirectAttributes rttr) throws Exception {
		logger.info("comment write");

		comService.commentWrite(vo);

		rttr.addAttribute("notice_no", vo.getNotice_no());
		rttr.addAttribute("page", scri.getPage());
		rttr.addAttribute("perPageNum", scri.getPerPageNum());
		rttr.addAttribute("searchType", scri.getSearchType());
		rttr.addAttribute("keyword", scri.getKeyword());

		return "redirect:/notice/noticeDetail";
	}

	//공지사항 댓글 수정
	@RequestMapping(value = "/commentModify", method = RequestMethod.GET)
	public void getReplyUpdate(@RequestParam("comments_no") int comments_no,
	      @ModelAttribute("scri") SearchCriteria scri, Model model) throws Exception {
	 logger.info("comment update");
	 
	 CommentVO vo = null;
	 
	 vo = comService.readComment(comments_no);
	 
	 model.addAttribute("readComment", vo);
	 model.addAttribute("scri", scri);
	}
	
	
	@RequestMapping(value = "/commentModify", method = RequestMethod.POST)
	public String commentModify(CommentVO vo, SearchCriteria scri, RedirectAttributes rttr) throws Exception {
		logger.info("comment update");

		comService.commentModify(vo);

		rttr.addAttribute("notice_no", vo.getNotice_no());
		rttr.addAttribute("page", scri.getPage());
		rttr.addAttribute("perPageNum", scri.getPerPageNum());
		rttr.addAttribute("searchType", scri.getSearchType());
		rttr.addAttribute("keyword", scri.getKeyword());

		return "redirect:/notice/noticeDetail";
	}

// 댓글 삭제
	@RequestMapping(value = "/commentDelete", method = RequestMethod.GET)
	public void getReplyDelete(@RequestParam("comments_no") int comments_no,
	      @ModelAttribute("scri") SearchCriteria scri, Model model) throws Exception {
	 logger.info("comment delete");
	 
	 CommentVO vo = null;
	 
	 vo = comService.readComment(comments_no);
	 
	 model.addAttribute("readComment", vo);
	 model.addAttribute("scri", scri);
	}
	
	@RequestMapping(value = "/commentDelete", method = RequestMethod.POST)
	public String commentDelete(CommentVO vo, SearchCriteria scri, RedirectAttributes rttr) throws Exception {
	 logger.info("comment delete");
	 
	 comService.commentDelete(vo);
	 
	 rttr.addAttribute("notice_no", vo.getNotice_no());
	 rttr.addAttribute("page", scri.getPage());
	 rttr.addAttribute("perPageNum", scri.getPerPageNum());
	 rttr.addAttribute("searchType", scri.getSearchType());
	 rttr.addAttribute("keyword", scri.getKeyword());
	 
	 return "redirect:/notice/noticeDetail";
	}
	
	//파일 다운로드
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
		response.getOutputStream().write(fileByte);
		response.getOutputStream().flush();
		response.getOutputStream().close();
	
	}
}
