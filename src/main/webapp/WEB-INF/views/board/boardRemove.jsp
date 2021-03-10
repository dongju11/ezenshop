<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<html>
<head>
 <title>자유 게시판</title>
 
 <!-- 제이쿼리 -->
 <script src='https://code.jquery.com/jquery-3.3.1.min.js'></script>
 <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="//unpkg.com/bootstrap@4/dist/css/bootstrap.min.css">
	<script src='//unpkg.com/jquery@3/dist/jquery.min.js'></script>
	<script src='//unpkg.com/popper.js@1/dist/umd/popper.min.js'></script>
	<script src='//unpkg.com/bootstrap@4/dist/js/bootstrap.min.js'></script>
 
</head>
<body>
	<jsp:include page="../common/header.jsp"></jsp:include>

<div id="root">
 <header>
  <h1>자유 게시판</h1>
 </header>

 <section id="container">
 
  <form role="form" method="post" autocomplete="off">
  
   <p>
    <label for="fr_no">글 번호</label>
    <input type="text" id="fr_no" name="fr_no" value="${delete}" readonly="readonly" />
   </p>
   
   <p>정말로 삭제하시겠습니까?</p>
   
   <p>
   
    <button type="submit">예, 삭제합니다.</button><br />
    <button type="button" id="cancel_btn">아니오, 삭제하지 않습니다.</button>
    
    
    <script>

    // 폼을 변수에 저장
    var formObj = $("form[role='form']"); 
    
    // 취소 버튼 클릭
    $("#cancel_btn").click(function(){   
    	self.location = "/controller/board/boardDetail?fr_no=${delete}"
 		   + "&page=${scri.page}"
 		   + "&perPageNum=${scri.perPageNum}"
 		   + "&searchType=${scri.searchType}"
 		   + "&keyword=${scri.keyword}";
     
    });
    </script>
   </p>
  </form>
 </section>
</div>
</body>
</html>
