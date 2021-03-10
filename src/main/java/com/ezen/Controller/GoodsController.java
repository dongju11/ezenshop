package com.ezen.Controller;

import java.io.File;
import java.util.List;

import javax.annotation.Resource;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import com.ezen.Other.PageMaker;
import com.ezen.Other.SearchCriteria;
import com.ezen.Service.CategoryService;
import com.ezen.Vo.CategoryVO;
import com.ezen.Vo.GoodsDetailVO;
import com.ezen.Vo.GoodsVO;
import com.ezen.Vo.MemberVO;
import com.ezen.utils.UploadFileUtils;

import net.sf.json.JSONArray;

@Controller
@RequestMapping("/goods/*")
public class GoodsController {
	
	
	@Inject
	CategoryService categoryService;
	
	@Resource(name="uploadPath")
	private String uploadPath;
	
	@RequestMapping(value = "/goodswriteForm", method = RequestMethod.GET)
	public void getgoodswriteForm(Model model) throws Exception{
		
		List<CategoryVO> category = null;
		category = categoryService.category();
		model.addAttribute("category", JSONArray.fromObject(category));
		 
	} 
	
	@RequestMapping(value = "/goodswriteForm", method = RequestMethod.POST)
	public String postgoodswriteForm(GoodsVO vo, MultipartFile file, HttpSession session) throws Exception{
		
		MemberVO member = (MemberVO)session.getAttribute("member");
		vo.setMEMBER_ID(member.getMEMBER_ID());
		
		String imgUploadPath = uploadPath + File.separator + "imgUpload";
		String ymdPath = UploadFileUtils.calcPath(imgUploadPath);
		String fileName = null;

		if(file.getOriginalFilename() != null && file.getOriginalFilename() != "") {
		 fileName =  UploadFileUtils.fileUpload(imgUploadPath, file.getOriginalFilename(), file.getBytes(), ymdPath); 
		 vo.setGOODS_IMAGE(File.separator + "imgUpload" + ymdPath + File.separator + fileName);
		 vo.setGOODS_THUMBIMG(File.separator + "imgUpload" + ymdPath + File.separator + "s" + File.separator + "s_" + fileName);
		} else {
		 fileName = File.separator + "images" + File.separator + "none.png";
		 vo.setGOODS_IMAGE(fileName);
		 vo.setGOODS_THUMBIMG(fileName);
		}
		
		categoryService.goodswrite(vo);
		
		return "redirect:/goods/goodslist";
	}
	
	@RequestMapping(value = "/goodslist", method = RequestMethod.GET)
	public void getgoodslist(Model model) throws Exception{
			
		List<GoodsDetailVO> list = categoryService.goodslist();
		
		model.addAttribute("goodslist", list);
		 
	} 
	
	// �긽�뭹 紐⑸줉 + �럹�씠吏� + 寃��깋
	@RequestMapping(value = "goods/mygoodsList", method = RequestMethod.GET)
	public void goodslistSearch(@ModelAttribute("scri") SearchCriteria scri, Model model, HttpSession session, GoodsVO vo) throws Exception {
				
		
		
		
		MemberVO member = (MemberVO)session.getAttribute("member");
		String MEMBER_ID = member.getMEMBER_ID();
		
		vo.setMEMBER_ID(MEMBER_ID);
		
		List<GoodsVO> list = categoryService.goodslistSearch(scri);
		
		model.addAttribute("mygoodsList", list);
		
		PageMaker goodspageMaker = new PageMaker();
		goodspageMaker.setCri(scri);
		//pageMaker.setTotalCount(adminService.listCount());
		goodspageMaker.setTotalCount(categoryService.countSearch(scri));
		model.addAttribute("pageMaker", goodspageMaker);
		
	}
	
	
	// �긽�뭹 議고쉶
	@RequestMapping(value = "/goodsdetail", method = RequestMethod.GET)
	public void getgoodsdetail(@RequestParam("n") int GOODS_NO, Model model) throws Exception{
			
		GoodsDetailVO goods = categoryService.goodsdetail(GOODS_NO);
		
		model.addAttribute("goods", goods);
		
		 
	} 
	
	//�긽�뭹 �닔�젙
	@RequestMapping(value = "/goodsmodify", method = RequestMethod.GET)
	public void getgoodsmodify(@RequestParam("n") int GOODS_NO, Model model) throws Exception{
		
			GoodsDetailVO goods = categoryService.goodsdetail(GOODS_NO);
			model.addAttribute("goods", goods);
			
			List<CategoryVO> category = null;
			category = categoryService.category();
			model.addAttribute("category", JSONArray.fromObject(category));
		 
	} 
	
	@RequestMapping(value = "/goodsmodify", method = RequestMethod.POST)
	public String postgoodsmodify(GoodsVO vo, MultipartFile file, HttpServletRequest req) throws Exception {
		
		if(file.getOriginalFilename()!= null && !file.getOriginalFilename().equals("")) {
			new File(uploadPath + req.getParameter("GOODS_IMAGE")).delete();
			new File(uploadPath + req.getParameter("GOODS_THUMBIMG")).delete();
			
			String imgUploadPath = uploadPath + File.separator + "imgUpload";
			String ymdPath = UploadFileUtils.calcPath(imgUploadPath);
			String fileName = UploadFileUtils.fileUpload(imgUploadPath, file.getOriginalFilename(), file.getBytes(), ymdPath);
			  
			vo.setGOODS_IMAGE(File.separator + "imgUpload" + ymdPath + File.separator + fileName);
			vo.setGOODS_THUMBIMG(File.separator + "imgUpload" + ymdPath + File.separator + "s" + File.separator + "s_" + fileName);
		} else {
			
			vo.setGOODS_IMAGE(req.getParameter("GOODS_IMAGE"));
			vo.setGOODS_THUMBIMG(req.getParameter("GOODS_THUMBIMG"));
		}
		
		categoryService.goodsModify(vo);
		
		return "redirect:/goods/goodslist";
		
	}
	
	// �긽�뭹 �궘�젣
	@RequestMapping(value = "/goodsdelete", method = RequestMethod.POST)
	public String postgoodsmodify(@RequestParam("n") int GOODS_NO) throws Exception {
		
		categoryService.goodsDelete(GOODS_NO);
		
		return "redirect:/goods/goodslist";
		
	}
	

}
