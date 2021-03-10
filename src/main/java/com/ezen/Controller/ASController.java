package com.ezen.Controller;


import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.ezen.Vo.ASVO;

import net.sf.json.JSONArray;

import com.ezen.Other.Criteria;
import com.ezen.Other.PageMaker;
import com.ezen.Service.ASService;

@Controller
@RequestMapping("/as/*")
public class ASController {

private static final Logger logger = LoggerFactory.getLogger(ASController.class);
 
 @Inject
 ASService service;
 
 // ����
 @RequestMapping(value ="/as", method = RequestMethod.GET)
 public void getSee() throws Exception{
	 logger.info("see");
 }
 
 @RequestMapping(value="/as", method = RequestMethod.POST)
 public String postSee(ASVO vo) throws Exception{
	 logger.info("post see");
	 
	 service.see();
	 
	 return "redirect:/";
 }
 
 // �� �ۼ� get
 @RequestMapping(value = "/aswrite", method = RequestMethod.GET)
	public void getWrite(/* Model model */) throws Exception {
  logger.info("get write");
  
	/*
	 * List<ASCategoryVO> ascate = null; ascate = service.ascate();
	 * model.addAttribute("ascate", JSONArray.fromObject(ascate));
	 */
 }

 // �� �ۼ� post
 @RequestMapping(value = "/aswrite", method = RequestMethod.POST)
 public String postWrite(ASVO vo/*, Model model*/) throws Exception {
  logger.info("post write");
  
	/*
	 * List<ASCategoryVO> ascate = null; ascate = service.ascate();
	 * model.addAttribute("ascate", JSONArray.fromObject(ascate));
	 */
  
  service.write(vo);
  
  return "redirect:/";
 }
 
  //��Ϻ���
 @RequestMapping(value ="/aslist", method = RequestMethod.GET)
 public void list(@ModelAttribute("cri")Criteria cri, Model model) throws Exception{
	 logger.info("get list");
	 
	 List<ASVO> asList = service.list(cri);
	 
	 model.addAttribute("asList", asList);
	 //����¡
	 PageMaker pageMaker = new PageMaker();
	 pageMaker.setCri(cri);
	 pageMaker.setTotalCount(service.listCount());
	 model.addAttribute("pageMaker", pageMaker);
 }
 
 // �� ��ȸ�ϱ�
 @RequestMapping(value ="/asdetail", method = RequestMethod.GET)
 public void getRead(@RequestParam("as_no") int as_no, Model model) throws Exception{
	 logger.info("get Detail");
	 
	 ASVO vo = service.read(as_no);
	 
	 model.addAttribute("read", vo);
 }
 
//�� �� ��
@RequestMapping(value = "/asupdate", method = RequestMethod.GET)
public void getModify(@RequestParam("as_no") int as_no, Model model) throws Exception {
	logger.info("get update");

	ASVO vo = service.read(as_no);

	model.addAttribute("modify", vo);

} 

@RequestMapping(value = "/asupdate", method = RequestMethod.POST)
public String postModify(ASVO vo) throws Exception {
logger.info("post modify");

service.update(vo);

return "redirect:./aslist";

}

// �� ����
@RequestMapping(value = "/asdelete", method = RequestMethod.GET)
public void getDelete(@RequestParam("as_no") int as_no, Model model) throws Exception {
	logger.info("get delete");
  
	model.addAttribute("delete", as_no);

}
 
@RequestMapping(value = "/asdelete", method = RequestMethod.POST)
public String postDelete(@RequestParam("as_no") int as_no) throws Exception {
 logger.info("post delete");
   
 service.delete(as_no);
 
 return "redirect:./aslist";
}


}
