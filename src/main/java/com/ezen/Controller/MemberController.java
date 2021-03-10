package com.ezen.Controller;

import java.io.IOException;


import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;
import java.util.Random;

import javax.inject.Inject;
import javax.mail.Message;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder; 
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.ezen.Service.MemberService;
import com.ezen.Vo.MemberVO;

import com.ezen.utils.NaverLoginBO;
import com.ezen.Service.KakaoService;
import com.github.scribejava.core.model.OAuth2AccessToken;

@Controller 
@RequestMapping("/member/*")
public class MemberController {
	
	String msg = "";

	int qwe = 1;
	private static final Logger Logger = LoggerFactory.getLogger(MemberController.class);

	@Inject
	MemberService service;
	
	/* NaverLoginBO */
	private NaverLoginBO naverLoginBO;
	private String apiResult = null;
	
	@Autowired
	private void setNaverLoginBO(NaverLoginBO naverLoginBO) {
	this.naverLoginBO = naverLoginBO;
	}
	 @Autowired
	 private KakaoService kakaoService;
	@Autowired
	BCryptPasswordEncoder passEncoder;
	
	@RequestMapping(value = "/memberinsert", method = RequestMethod.GET)
	public void getMemberinsert() throws Exception {
		Logger.info("1");
	}
	
	@RequestMapping(value = "/memberinsert", method = RequestMethod.POST)
	public String postMemberinsert(MemberVO vo, HttpServletResponse response) throws Exception {
		Logger.info("2");
		
		String inputPass = vo.getMEMBER_PW(); 
		String pass = passEncoder.encode(inputPass);
		vo.setMEMBER_PW(pass);
		
		service.memberinsert(vo);
		
		 return "redirect:/";
	}
	
	@RequestMapping(value = "/login", method = RequestMethod.GET)
	public String getlogin(Model model, HttpSession session) throws Exception {
		Logger.info("get login");
		/* �꽕�씠踰꾩븘�씠�뵒濡� �씤利� URL�쓣 �깮�꽦�븯湲� �쐞�븯�뿬 naverLoginBO�겢�옒�뒪�쓽 getAuthorizationUrl硫붿냼�뱶 �샇異� */
		String naverAuthUrl = naverLoginBO.getAuthorizationUrl(session);
 		model.addAttribute("url", naverAuthUrl);
		
		return "/member/login";
	}
	
	 @RequestMapping("/kakaologin")
	 public String kakaologin(@RequestParam(value = "code", required = false) String code, HttpSession session) throws Exception{
	        String access_Token = kakaoService.getAccessToken(code);
	        HashMap<String, Object> userInfo = kakaoService.getUserInfo(access_Token);
	      
	        session.setAttribute("member",userInfo.get("nickname")); //�꽭�뀡 �깮�꽦
	        return "redirect:/";
	

}
	 
	 @RequestMapping(value = "/login", method = RequestMethod.POST)
	 public String postSignin(MemberVO vo, HttpServletRequest req, RedirectAttributes rttr) throws Exception {
	  Logger.info("post login");
	    
	  try { 
	  MemberVO login = service.login(vo);  
	  HttpSession session = req.getSession();
	  
	  boolean passMatch = passEncoder.matches(vo.getMEMBER_PW(), login.getMEMBER_PW());
	  
	  if(login != null && passMatch ) {
	   session.setAttribute("member", login);
	  } else {
	   session.setAttribute("member", null);
	   rttr.addFlashAttribute("msg", false);
	   
	   return "redirect:/member/login";
	  }  
	  }catch(NullPointerException e){
	
		   rttr.addFlashAttribute("msg", false);
		   
		   return "redirect:/member/login";
	  }
	  return "redirect:/";
	 }
		
		// �꽕�씠踰� 濡쒓렇�씤 �꽦怨듭떆 callback�샇異� 硫붿냼�뱶
	@RequestMapping(value = "/login_result", method = { RequestMethod.GET, RequestMethod.POST })
	public String login_result(Model model, @RequestParam String code, @RequestParam String state, HttpSession session)
			throws IOException, ParseException {
		System.out.println("�뿬湲곕뒗 callback");
		
		
		
		OAuth2AccessToken oauthToken;
		oauthToken = naverLoginBO.getAccessToken(session, code, state);
		// 1. 濡쒓렇�씤 �궗�슜�옄 �젙蹂대�� �씫�뼱�삩�떎.
		apiResult = naverLoginBO.getUserProfile(oauthToken); // String�삎�떇�쓽 json�뜲�씠�꽣
		/**
		 * apiResult json 援ъ“ {"resultcode":"00", "message":"success",
		 * "response":{"id":"33666449","nickname":"shinn****","age":"20-29","gender":"M","email":"sh@naver.com","name":"\uc2e0\ubc94\ud638"}}
		 **/
		// 2. String�삎�떇�씤 apiResult瑜� json�삎�깭濡� 諛붽퓞
		JSONParser parser = new JSONParser();
		Object obj = parser.parse(apiResult);
		JSONObject jsonObj = (JSONObject) obj;

		// 3. �뜲�씠�꽣 �뙆�떛
		// Top�젅踰� �떒怨� _response �뙆�떛
		JSONObject response_obj = (JSONObject) jsonObj.get("response");
		// response�쓽 nickname媛� �뙆�떛
		String nickname = (String) response_obj.get("nickname");
		System.out.println(nickname);
		// 4.�뙆�떛 �땳�꽕�엫 �꽭�뀡�쑝濡� ���옣
		session.setAttribute("member", nickname); // �꽭�뀡 �깮�꽦
		model.addAttribute("result", apiResult);
		return "redirect:/";
	}

//濡쒓렇�븘�썐
	@RequestMapping(value = "/logout", method = RequestMethod.GET)
	public String logout(HttpSession session) throws Exception {
		Logger.info("get logout");

		session.invalidate();

		// kakao restapi 媛앹껜 �꽑�뼵

		return "redirect:/";
	}

	@RequestMapping(value = "/mypageConfirm", method = RequestMethod.GET)
	public void getMypageConfirm() throws Exception {
		Logger.info("get mypageConfirm");
	}


	@RequestMapping(value = "/mypageConfirm", method = RequestMethod.POST)
	public String postMypageConfirm(Model model, MemberVO vo, RedirectAttributes rttr, HttpServletResponse response) throws Exception {
		Logger.info("post mypageConfirm");
	
		 MemberVO login  = service.login (vo);
		
		 boolean pwChk = passEncoder.matches(vo.getMEMBER_PW(), login.getMEMBER_PW());
		 
		 if(login != null && pwChk) {
			 return "redirect:/member/mypage";

		 } else {
			 rttr.addFlashAttribute("msg", false);
		  return "redirect:/member/mypageConfirm";
		 }  
	}
	@RequestMapping(value = "/mypage")
	public String mypage() throws Exception {
	
		return "/member/mypage";
	}

	@RequestMapping(value = "/modify_withdrawal")
	public String modify_withdrawal() throws Exception {

		return "/member/modify_withdrawal";
	}

	@RequestMapping(value = "/modify", method = RequestMethod.GET)
	public void getModify() throws Exception {
		Logger.info("get modify");
	}

	// �쉶�썝�젙蹂� �닔�젙 post
	@RequestMapping(value = "/modify", method = RequestMethod.POST)
	public String postModify(HttpSession session, MemberVO vo) throws Exception {
		Logger.info("post modify");
		String inputPass = vo.getMEMBER_PW(); 
		String pass = passEncoder.encode(inputPass);
		vo.setMEMBER_PW(pass);
		
		
		service.modify(vo);
		session.invalidate();
		return "redirect:/";
	}

	// �쉶�썝 �깉�눜 get
	@RequestMapping(value = "/withdrawal", method = RequestMethod.GET)
	public void getwithdrawal() throws Exception {
		Logger.info("get withdrawal");
	}

	// �쉶�썝 �깉�눜 post
	@RequestMapping(value = "/withdrawal", method = RequestMethod.POST)
	public String postWithdrawal(HttpSession session, MemberVO vo, RedirectAttributes rttr,HttpServletRequest req) throws Exception {
		Logger.info("post withdrawal");
		 
		 
	
		 MemberVO login = service.login(vo);
		 
		 boolean pwCheck = passEncoder.matches(vo.getMEMBER_PW(), login.getMEMBER_PW());
		 
		 if(login != null && pwCheck) {
			 service.withdrawal(vo);
				session.invalidate();
				return "redirect:/";
		 } else {
		 
		  rttr.addFlashAttribute("msg", false);
		  return  "redirect:/member/withdrawal";
		 }  

		}
		
	
	// �쉶�썝 �솗�씤
	@ResponseBody
	@RequestMapping(value = "/idCheck", method = RequestMethod.POST)
	public int postIdCheck(HttpServletRequest req) throws Exception {
		Logger.info("post idCheck");

	 String MEMBER_ID = req.getParameter("MEMBER_ID");
	System.out.println(MEMBER_ID);

	 MemberVO idCheck =  service.idCheck(MEMBER_ID);
	
	 int result = 0;
	 
	 if(idCheck != null) {
	  result = 1;
	 } 
	 return result;
	 
	}


	@RequestMapping(value = "/find_Id", method = RequestMethod.GET)
	public void getFind_Id() throws Exception {
		Logger.info("get find_Id");
	
	}

	// �쉶�썝�젙蹂� �닔�젙 post
	@RequestMapping(value = "/find_Id", method = RequestMethod.POST)
	public String postFind_Id(MemberVO vo, Model model, RedirectAttributes rttr) throws Exception {
		String find_Id = service.find_Id(vo);

		if (find_Id == null) {
			rttr.addFlashAttribute("msg", false);
			return "redirect:/member/find_Id";
		}
		
			model.addAttribute("id", find_Id);
			return "/member/findId_Result";
		}
	

	@RequestMapping(value = "/findId_Result")
	public String getfindId_Result() throws Exception {

		return "/member/findId_Result";
	}

	@RequestMapping(value = "/find_Pw", method = RequestMethod.GET)
	public void getFind_Pw() throws Exception {
		Logger.info("get find_Pw");
	}

	// �쉶�썝�젙蹂� �닔�젙 post
	@RequestMapping(value = "/find_Pw", method = RequestMethod.POST)
	public String postFind_Pw(String MEMBER_EMAIL, String MEMBER_ID, HttpSession session2,MemberVO vo, Model model, RedirectAttributes rttr, String[] args) throws Exception {
		
		
		String find_Pw = service.find_Pw(vo);
		
		StringBuffer temp =	new StringBuffer();
           Random rnd = new Random();
        
           
         
           
           for(int i=0;i<5;i++)
           {
               int rIndex = rnd.nextInt(3);
               switch (rIndex) {
               case 0:
                   // a-z
                   temp.append((char) ((int) (rnd.nextInt(26)) + 97));
                   break;
               case 1:
                   // A-Z
                   temp.append((char) ((int) (rnd.nextInt(26)) + 65));
                   break;
               case 2:
                   // 0-9
                   temp.append((rnd.nextInt(10)));
                   break;
               }
           }
  		 
           String host = "smtp.naver.com"; 
           final String username = "dkdlxl156"; //�꽕�씠踰� �씠硫붿씪 二쇱냼以� @ naver.com�븵二쇱냼留� 湲곗옱�빀�땲�떎. 
           final String password = "sldoal147"; //�꽕�씠踰� �씠硫붿씪 鍮꾨�踰덊샇瑜� 湲곗옱�빀�땲�떎. 
           int port=465; // 硫붿씪 �궡�슜 
           
           String recipient = vo.getMEMBER_EMAIL();//硫붿씪�쓣 諛쒖넚�븷 �씠硫붿씪 二쇱냼瑜� 湲곗옱�빐 以띾땲�떎. 
           String subject = "EZENSHOP �엫�떆鍮꾨�踰덊샇 �엯�땲�떎."; 
           String content =  "�엫�떆踰덊샇�뒗" + temp + "�엯�땲�떎." ;

          
           
           Properties props = System.getProperties(); 
           props.put("mail.smtp.host", host); 
           props.put("mail.smtp.port", port); 
           props.put("mail.smtp.auth", "true"); 
           props.put("mail.smtp.ssl.enable", "true"); 
           props.put("mail.smtp.ssl.trust", host); 
           Session session = Session.getDefaultInstance(props, new javax.mail.Authenticator() {
        	   String un=username; String pw=password; 
        	   protected PasswordAuthentication getPasswordAuthentication() {
        		   return new PasswordAuthentication(un, pw); } });

          
   		session.setDebug(true); //for debug 
		Message mimeMessage = new MimeMessage(session); 
		mimeMessage.setFrom(new InternetAddress("dkdlxl156@naver.com"));
		mimeMessage.setRecipient(Message.RecipientType.TO, new InternetAddress(recipient)); 
		mimeMessage.setSubject(subject); 
		mimeMessage.setText(content); 
		
		if (find_Pw == null) {
			rttr.addFlashAttribute("msg", false);
			return "redirect:/member/find_Pw";
		}	
			model.addAttribute("pw", temp);
			String pass = passEncoder.encode(temp);
			vo.setMEMBER_PW(pass);
		
			
			service.modifyPw(vo);
			
	
			Transport.send(mimeMessage);
			session2.invalidate();
 			return "/member/findPw_Result";
		}
	
	@RequestMapping(value = "/findPw_Result")
	public String getfindPw_Result() throws Exception {

		return "/member/findPw_Result";
	}
	
	 @RequestMapping(value = "/memberlist", method = RequestMethod.GET)
	 public void getList(Model model) throws Exception {
		  
		  List list = null;
		  list = service.list();
		  model.addAttribute("list", list);
		 }
		}