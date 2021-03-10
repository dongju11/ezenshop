<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<html>
<head>
	<title>Home</title>
	<!-- <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="//unpkg.com/bootstrap@4/dist/css/bootstrap.min.css">
	<script src='//unpkg.com/jquery@3/dist/jquery.min.js'></script>
	<script src='//unpkg.com/popper.js@1/dist/umd/popper.min.js'></script>
	<script src='//unpkg.com/bootstrap@4/dist/js/bootstrap.min.js'></script> -->
	
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	

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

<div class ="container">
	<header>
	<h2>교환/반품/환불 게시판</h2>
	</header>
<section id="container">
 
  <form role="form" method="post" autocomplete="off">
  
   <p>
   	<label for ="as_no"></label><input type ="hidden" id ="no" name ="as_no" value ="${delete}"/>
   </p>
   <p>정말로 삭제하시겠습니까?</p>
   
   <p>
   	<button type = "submit">예, 삭제합니다.</button>
   	<button id ="cancel_btn">아니오, 삭제하지 않습니다.</button>
 
   	<script>
		var formObj = $("form[role='form']");

		//취소버튼
			$("#cancel_btn").click(function(){

				formObj.attr("action", "./myASWroteList?as_no=" + $("#as_no").val());
				formObj.attr("method", "get");
				formObj.submit();
				
			});
		
   	</script>
   </p>
  </form>
	

 </section>
 
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
</div>
</body>
</html>