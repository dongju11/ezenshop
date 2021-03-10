<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<!DOCTYPE html>
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
<title>Insert title here</title>

</head>
<body>
<jsp:include page="../common/header.jsp"></jsp:include>

<div class="container">
<div class="col-lg-0">	
			<div class="jumbotron" style="padding-top: 20px;">				
			<form role="form" method="post" autocomplete="off">

	
	<h3 style="text-align: center;">비밀번호 찾기</h3>
	<p>
		<div class="input_area">
		<label for="MEMBER_ID">아이디</label> <input type="text"
			id="MEMBER_ID" name="MEMBER_ID" value="${member.MEMBER_ID}" />
		</div>
	</p>

	<p>
		<div class="input_area">
		<label for="MEMBER_EMAIL">이메일</label> <input type="email"
			id="MEMBER_EMAIL" name="MEMBER_EMAIL" value="${member.MEMBER_EMAIL}" />
		</div>
	</p>
	<p>
		<div class="input_area">
		<label for="MEMBER_NAME">이름</label> <input type="text"
			id="MEMBER_NAME" name="MEMBER_NAME" value="${member.MEMBER_NAME}" />
		</div>
	</p>
	


	
		<button type="submit" class="btn btn-danger">찾기</button>
		<button type="button" class="btn btn-danger" onclick="location.href='login'">돌아가기</button>
	
		<button type="button" class="btn btn-danger" onclick="location.href='find_Id'">아이디 찾기</button>
	
	<c:if test="${msg == false }">
			<p>회원 정보가 없습니다.</p>
		</c:if>
</form>
</div>
</div>
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