package com.ezen.Other;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;

import com.ezen.Vo.NoticeVO;

@Component("noticeFileUtils")
public class noticeFileUtils {
	private static final String filePath = "C:\\mp\\file\\"; // 占쎈솁占쎌뵬占쎌뵠 占쏙옙占쎌삢占쎈쭍 占쎌맄燁삼옙
	
	public List<Map<String, Object>> parseInsertFileInfo(NoticeVO vo, 
			MultipartHttpServletRequest mpRequest) throws Exception{
		
		/*
			Iterator占쏙옙 占쎈쑓占쎌뵠占쎄숲占쎈굶占쎌벥 筌욌쵑鍮�筌ｏ옙? 占쎈퓠占쎄퐣 �뚎됱젂占쎈�∽옙�몵嚥≪뮆占쏙옙苑� 占쎌젟癰귣�占쏙옙 占쎈섯占쎈선占쎌궞 占쎈땾 占쎌뿳占쎈뮉 占쎌뵥占쎄숲占쎈읂占쎌뵠占쎈뮞占쎌뿯占쎈빍占쎈뼄.
			List占쎄돌 獄쏄퀣肉댐옙占� 占쎈떄筌△뫁�읅占쎌몵嚥∽옙 占쎈쑓占쎌뵠占쎄숲占쎌벥 占쎌젔域뱀눘�뵠 揶쏉옙占쎈뮟占쎈릭筌욑옙筌랃옙, Map占쎈쾻占쎌벥 占쎄깻占쎌삋占쎈뮞占쎈굶占쏙옙 占쎈떄筌△뫁�읅占쎌몵嚥∽옙 占쎌젔域뱀눛釉� 占쎈땾揶쏉옙 占쎈씨占쎈뮸占쎈빍占쎈뼄.
			Iterator占쎌뱽 占쎌뵠占쎌뒠占쎈릭占쎈연 Map占쎈퓠 占쎌뿳占쎈뮉 占쎈쑓占쎌뵠占쎄숲占쎈굶占쎌뱽 while�눧紐꾩뱽 占쎌뵠占쎌뒠占쎈릭占쎈연 占쎈떄筌△뫁�읅占쎌몵嚥∽옙 占쎌젔域뱀눛鍮�占쎈빍占쎈뼄.
		*/
		
		Iterator<String> iterator = mpRequest.getFileNames();
		
		MultipartFile multipartFile = null;
		String originalFileName = null;
		String originalFileExtension = null;
		String storedFileName = null;
		
		List<Map<String, Object>> list = new ArrayList<Map<String,Object>>();
		Map<String, Object> listMap = null;
		
		int notice_no = vo.getNotice_no();
		
		File file = new File(filePath);
		if(file.exists() == false) {
			file.mkdirs();
		}
		
		while(iterator.hasNext()) {
			multipartFile = mpRequest.getFile(iterator.next());
			if(multipartFile.isEmpty() == false) {
				originalFileName = multipartFile.getOriginalFilename();
				originalFileExtension = originalFileName.substring(originalFileName.lastIndexOf("."));
				storedFileName = getRandomString() + originalFileExtension;
				
				file = new File(filePath + storedFileName);
				multipartFile.transferTo(file);
				listMap = new HashMap<String, Object>();
				listMap.put("NOTICE_NO", notice_no);
				listMap.put("ORGFILE_NAME", originalFileName);
				listMap.put("NEWFILE_NAME", storedFileName);
				listMap.put("FILE_SIZE", multipartFile.getSize());
				list.add(listMap);
			}
		}
		return list;
	}
	
	public List<Map<String, Object>> parseUpdateFileInfo(NoticeVO vo, String[] files, String[] fileNames, MultipartHttpServletRequest mpRequest) throws Exception{ 
		Iterator<String> iterator = mpRequest.getFileNames();
		MultipartFile multipartFile = null; 
		String originalFileName = null; 
		String originalFileExtension = null; 
		String storedFileName = null; 
		List<Map<String,Object>> list = new ArrayList<Map<String,Object>>();
		Map<String, Object> listMap = null; 
		int notice_no = vo.getNotice_no();
		while(iterator.hasNext()){ 
			multipartFile = mpRequest.getFile(iterator.next()); 
			if(multipartFile.isEmpty() == false){ 
				originalFileName = multipartFile.getOriginalFilename(); 
				originalFileExtension = originalFileName.substring(originalFileName.lastIndexOf(".")); 
				storedFileName = getRandomString() + originalFileExtension; 
				multipartFile.transferTo(new File(filePath + storedFileName)); 
				listMap = new HashMap<String,Object>();
				listMap.put("IS_NEW", "Y");
				listMap.put("NOTICE_NO", notice_no); 
				listMap.put("ORGFILE_NAME", originalFileName);
				listMap.put("NEWFILE_NAME", storedFileName); 
				listMap.put("FILE_SIZE", multipartFile.getSize()); 
				list.add(listMap); 
			} 
		}
		if(files != null && fileNames != null){ 
			for(int i = 0; i<fileNames.length; i++) {
					listMap = new HashMap<String,Object>();
                    listMap.put("IS_NEW", "N");
					listMap.put("FILE_NO", files[i]); 
					list.add(listMap); 
			}
		}
		return list; 
	}
	
	
	public static String getRandomString() {
		return UUID.randomUUID().toString().replaceAll("-", "");
	}

}
