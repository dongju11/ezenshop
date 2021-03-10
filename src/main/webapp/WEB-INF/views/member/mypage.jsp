<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<html>
<head>
	<title>Home</title>
	    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <script src='https://code.jquery.com/jquery-3.3.1.min.js'></script>	 
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
	<div class="container">		
		<div class="col-lg-0">	
			<div class="jumbotron" style="padding-top: 20px;">
				<h3 style="text-align: center;">마이페이지</h3>
			
				<div class="form-group row">
					<div class="col-md-6 button1  mt-2">
						<button type="button" class="btn btn-danger btn-block" onclick="location.href='${pageContext.request.contextPath}/as/as'">반품/교환/환불</button>
					</div>
					<div class="col-md-6 button2  mt-2">
						<button type="button" class="btn btn-danger btn-block" onclick="location.href='${pageContext.request.contextPath}/shop/orderList'">주문/배송조회</button>
					</div>
				
					<div class="col-md-6 button4  mt-5">
						<button type="button" class="btn btn-danger btn-block" onclick="location.href='${pageContext.request.contextPath}/member/myWroteList'">내 작성내역 조회</button>
					</div>
					
					<div class="col-md-6 button6  mt-5">
						<button type="button" class="btn btn-danger btn-block" onclick="location.href='modify_withdrawal'">회원정보 수정/탈퇴</button>
					</div>
					
					<div class="col-md-6 button7  mt-5">
						<button type="button" class="btn btn-danger btn-block" onclick="location.href='${pageContext.request.contextPath}/shop/jjimList'">위시리스트</button>
					</div>
					
				</div>
					<div>
						<button type="button" class="btn btn-danger btn-block" onclick="location.href='../'">메인으로</button>
					</div>
				
			</div>
		</div>
	</div>

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