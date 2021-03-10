<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<html>

<head>
	<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
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
<jsp:include page="../common/adminHeader.jsp"></jsp:include>
	
<section id="container">
 
  <form role="form" method="post" autocomplete="off">
  <h2>교환/반품/환불</h2>
   <p>
   	<label for ="as_no"></label><input type ="hidden" id ="no" name ="as_no" value ="${read.as_no}" readonly = "readonly"/>
   </p>
   </form>
   <p>
   	<label for ="order_no">주문번호</label><input type ="text" id ="order_id" name ="order_title" value ="${read.order_id}" readonly ="readonly"/>
   </p>
    <p>
    <label for="as_writer">작성자</label><input type ="text" id="writer" name="member_id" value="${read.member_id}" readonly = "readonly" />
   </p>
   <p>
    <label for="as_title">제목</label><input type="text" id="title" name="as_title" value ="${read.as_title}" readonly= "readonly"/>
   </p>
    <p>
    	<label for ="as_category">분류</label><input type ="text" id ="category" name ="as_category" value ="${read.as_category}" readonly ="readonly" />
    <!-- <label for="as_content">문의사항</label><input type ="text" id="content" name="as_content"/> -->
  <!--   <label for ="as_category">분류</label>
    	<select id ="category" name ="as_category">
    		<option title="">사유선택</option>
    		<option value="교환">교환</option>
    		<option value="환불">환불</option>
    		<option value="반품">반품</option>
    	</select> -->
   </p>
   <%--  <label for="as_content">문의사항</label><textarea id="content" name="as_content" value ="${read.as_content}" readonly = "readonly"> ${read.as_content}</textarea> --%>
    <!--   <label for ="as_catename">문의 분류</label>
    	<select name ="as_category" id ="as_catename" readonly = "readonly">
    		<option title=""></option>
    		<option value="교환">교환</option>
    		<option value="환불">환불</option>
    		<option value="반품">반품</option>
    	</select> -->
  
   <p>
    <label for="as_content">사유</label><input type ="text" id="content" name="as_content" value="${read.as_content}" placeholder="사유를 입력하세요." readonly="readonly"/>
   </p>
   <p>
   	<label for ="as_account">환불 계좌</label>
   	<select>
   		<option title ="">은행명</option>
   		<option value ="국민">국민</option>
   		<option value ="신한">신한</option>
   		<option value ="농협">농협</option>
	</select>
   	<input type ="text" id ="account" name ="as_account" value="${read.as_account}" readonly = "readonly"/>
   </p>
   <p>
   	<label>작성 날짜</label> <span><fmt:formatDate value="${read.as_regdate}" pattern="yyyy-MM-dd" /></span>
   </p>
   <p>
   <!-- 	<button id ="modify_btn">수정</button>
   	<button id ="delete_btn">삭제</button> -->
   	
   	<script>
		var formObj = $("form[role='form']");
		//수정 버튼
		$("#modify_btn").click(function(){

			formObj.attr("action", "./asupdate");
			formObj.attr("method", "get");
			formObj.submit();
			
			});
		//삭제버튼
		$("#delete_btn").click(function(){

			formObj.attr("action", "./asdelete");
			formObj.attr("method", "get");
			formObj.submit();
			
			});
		
   	</script>
   </p>
  

 </section>


<jsp:include page="../common/adminFooter.jsp"></jsp:include>
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
</body>
</html>