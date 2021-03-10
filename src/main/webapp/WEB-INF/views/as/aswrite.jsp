<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<html>
<head>
	<meta charset="utf-8">
	
	<title>Home</title>

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
</head>
<body>
<jsp:include page="../common/header.jsp"></jsp:include>

<section id="container">
<div class="col-sm-5">	
			<div class="jumbotron" style="padding-top: 20px;">
				<form role="form" method="post" autocomplete="off">
					
 <h2>교환/반품/환불 요청</h2>
 <br>
 	<p>
    <label for="writer">작성자</label><input type ="text" id="writer" name="member_id" value = "${member.MEMBER_ID}" readonly ="readonly" class="form-control"/>
   </p>
 	
  	<p>
  		<label for ="order_id">주문번호</label><input type ="text" id ="order_id" name ="order_id" class="form-control"/>
  	</p>
  	  
   <p>
    <label for="as_title">제목</label><input type="text" id="title" name="as_title" placeholder ="제목을 입력하세요" class="form-control"/>
   </p>
   
    <!-- <label for="as_content">문의사항</label><input type ="text" id="content" name="as_content"/> -->
    <label for ="as_category">분류</label>
    	<select id ="category" name ="as_category" class="form-control" >
    		<option title="">사유선택</option>
    		<option value="교환">교환</option>
    		<option value="환불">환불</option>
    		<option value="반품">반품</option>
    	</select>
   </p>
   <p>
    <label for="as_content">사유</label><input type ="text" id="content" name="as_content" placeholder="사유를 입력하세요." class="form-control"/>
   </p>
  
   <p>
   	<label for ="as_account">은행명</label>
   	<select class="form-control">
   		<option title ="">은행명</option>
   		<option value ="국민">국민</option>
   		<option value ="신한">신한</option>
   		<option value ="농협">농협</option>
	</select>
   	<label for ="as_account">환불 계좌</label><input type ="text" id ="account" name ="as_account" class="form-control" />
   </p>
   <p>
    <button type="submit" class="btn btn-danger">작성</button>
    <button type="button" class="btn btn-danger" onclick="location.href='..'">취소</button>
   </p>  
  </form>

 </section>
 </form>
</div>
</div>
</body>
<jsp:include page="../common/footer.jsp"></jsp:include>
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

</html>