package com.ezen.Service;

import java.util.List;
import java.util.Map;

import com.ezen.Other.Criteria;
import com.ezen.Vo.ASVO;
import com.ezen.Vo.boardVO;
import com.ezen.Vo.qnaVO;
import com.ezen.Vo.reportVO;

public interface myWroteListService {

		//�옄�쑀寃뚯떆�뙋
		public List<boardVO> freeWroteList(Criteria cri) throws Exception;
		
		//�옄�쑀 寃뚯떆�뙋 寃뚯떆臾� 珥� 媛��닔
		public int freeListCount() throws Exception;
		
		//�떊怨� 寃뚯떆�뙋
		public List<reportVO> reportWroteList(Criteria cri) throws Exception;
		
		//�떊怨� 寃뚯떆�뙋 寃뚯떆臾� 珥� 媛��닔
		public int reportListCount() throws Exception;
		
		//臾몄쓽 寃뚯떆�뙋
		public List<qnaVO> qnaWroteList(Criteria cri) throws Exception;
		
		//臾몄쓽 寃뚯떆�뙋 寃뚯떆臾� 珥� 媛��닔
		public int qnaListCount() throws Exception;
		
		// 泥⑤��뙆�씪 �떎�슫
		public Map<String, Object> selectFileInfo(Map<String, Object> map) throws Exception;
		
		//환불게시판
		public List<ASVO> ASWroteList(Criteria cri) throws Exception;
		
		public int ASListCount() throws Exception;
		
}
