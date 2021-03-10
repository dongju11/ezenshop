<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<html>
<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<title>Home</title>
	
	<meta name="viewport" content="width=device-width, initial-scale=1">
	

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
   
<title>회원정보 수정,탈퇴</title>
</head>
<body>
<jsp:include page="../common/header.jsp"></jsp:include>

		<div class="container">		
		<div class="col-sm-10">	
			<div class="jumbotron" style="padding-top: 20px;">
				<form role="form" method="post" autocomplete="off">
					<h3 style="text-align: center;">수정 및 탈퇴</h3>
					

		<button type="button" class="btn btn-danger" onclick="location.href='modify'">회원정보 수정</button>
		<button type="button" class="btn btn-danger" onclick="location.href='withdrawal'">회원정보 탈퇴</button>
		
		</form>
		</div>
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