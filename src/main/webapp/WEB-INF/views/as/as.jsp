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
	
</head>
<body>
<jsp:include page="../common/header.jsp"></jsp:include>

<div class="container">
	<div class="col-lg-0">
		<div class="jumbotron" style="padding-center: 20px;">

	<div>
		<h2>교환 및 환불 절차 안내</h2>
		
				<p>정상 제품의 경우, 제품 수령일로부터 7일 이내에 교환/반품/환불이 가능합니다.</p>
		
				<p>제품의 훼손으로 인해 재판매가 어려울 경우 교환 및 반품이 불가능 할 수 있습니다</p>
		
				<p>반품 및 교환 시에는 반드시 정품박스에 동봉하여 보내주셔야 정상적인 처리가 가능합니다</p>
			
				<p>제품의 불량이나 파손 이외의 교환이나 반품 운송료는 고객님 부담입니다</p>
		
				<p>교환 및 반품이 처리되기까지 5일에서 7일 정도의 시간이 소요됩니다</p>
		
				<p>반품의 경우, 결제대금의 취소 및 환불은 제품 회수 후에 이루어집니다</p>
	
	</div>
	
	
	<button type="button"  class="btn btn-danger" onclick="location.href='../as/aswrite'">확인</button>
	<button type="button"  class="btn btn-danger" onclick="location.href='../'">취소</button>
	
	</div>
	</div>
	</div>
	
 	<script>
		var formObj = $("form[role='form']");
		//취소 버튼
		$("#cancel_btn").click(function(){

			formObj.attr("action", "../member/mypage);
			formObj.attr("method", "get");
			formObj.submit();
			
			});
   	</script>

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
	
	</body>
</html>