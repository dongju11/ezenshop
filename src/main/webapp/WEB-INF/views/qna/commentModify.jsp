<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<html>
<head>

 <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="//unpkg.com/bootstrap@4/dist/css/bootstrap.min.css">
	<!-- Animate.css -->
	<link rel="stylesheet" href="/controller/resources/css/animate.css">
	<!-- Icomoon Icon Fonts-->
	<link rel="stylesheet" href="/controller/resources/css/icomoon.css">

	<!-- Owl Carousel -->
	<link rel="stylesheet" href="/controller/resources/css/owl.carousel.min.css">
	<link rel="stylesheet" href="/controller/resources/css/owl.theme.default.min.css">
	<!-- Theme style  -->
	<link rel="stylesheet" href="/controller/resources/css/style.css">
	<!-- Modernizr JS -->
	<script src="/controller/resources/js/modernizr-2.6.2.min.js"></script>	
 
 <title>댓글 수정</title>
</head>
<body>
<jsp:include page="../common/header.jsp"></jsp:include>

<div class="container">
 <header>
  <h1>댓글 수정</h1>
 </header>

 <section id="container">
 
  <form role="form" method="post" autocomplete="off">
   
   <input type="hidden" id="qna_no" name="qna_no" value="${readComment.qna_no}" readonly="readonly" />
   <input type="hidden" id="comments_no" name="comments_no" value="${readComment.comments_no}" readonly="readonly" /> 
   <input type="hidden" id="page" name="page" value="${scri.page}" readonly="readonly" />
   <input type="hidden" id="perPageNum" name="perPageNum" value="${scri.perPageNum}" readonly="readonly" />
   <input type="hidden" id="searchType" name="searchType" value="${scri.searchType}" readonly="readonly" />
   <input type="hidden" id="keyword" name="keyword" value="${scri.keyword}" readonly="readonly" />
   <div class="col-xs-10 col-sm-10">
   <div class="col-10">
   <div class="form-group">
   <p>
    <label for="content">글 내용</label><textarea id="content" name="comments_content" class="form-control">${readComment.comments_content }</textarea>
   </p>
    </div>
   <p>
    <button type="submit" class="btn btn-dark">수정</button>
    <button type="button" id="cancel_btn" class="btn btn-secondary">취소</button>
    
    <script>
    // 폼을 변수에 저장
    var formObj = $("form[role='form']"); 
    
    // 취소 버튼 클릭
    $("#cancel_btn").click(function(){   
    	self.location = "/controller/qna/QnaDetail?qna_no=${readComment.qna_no}"
    		   + "&page=${scri.page}"
    		   + "&perPageNum=${scri.perPageNum}"
    		   + "&searchType=${scri.searchType}"
    		   + "&keyword=${scri.keyword}";
    });
    </script>
   </p>  
   </div>
   </div>
  </form>
 </section>
</div>
<!-- jQuery -->
	<script src="/controller/resources/js/jquery.min.js"></script>
	<!-- jQuery Easing -->
	<script src="/controller/resources/js/jquery.easing.1.3.js"></script>
	<!-- Bootstrap -->
	<script src="/controller/resources/js/bootstrap.min.js"></script>
	<!-- Carousel -->
	<script src="/controller/resources/js/owl.carousel.min.js"></script>
	<!-- Stellar -->
	<script src="/controller/resources/js/jquery.stellar.min.js"></script>
	<!-- Waypoints -->
	<script src="/controller/resources/js/jquery.waypoints.min.js"></script>
	<!-- Counters -->
	<script src="/controller/resources/js/jquery.countTo.js"></script>
	<!-- MAIN JS -->
	<script src="/controller/resources/js/main.js"></script>
<jsp:include page="../common/footer.jsp"></jsp:include>
</body>
</html>