<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<!DOCTYPE html>
<html>
<head>
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
	<jsp:include page="../common/footer.jsp"></jsp:include>

	<form role="form" method="post" autocomplete="off">
	
		<h3 style="text-align: center;">비밀번호 인증</h3>
		<p>
		<label for="MEMBER_ID">아이디 </label> 
		<input type="text" id="MEMBER_ID" name="MEMBER_ID" value="${member.MEMBER_ID}"/>
	</p>
		
		<p>
			<label for="MEMBER_PW">비밀번호 </label> <input type="password"
				id="MEMBER_PW" name="MEMBER_PW" />
		</p>

		<p>
			<button type="submit" >확인</button>
		</p>

		<p>
		
			<button type="button" onclick="location.href='/controller/'">취소</button>
		</p>


		<c:if test="${msg == false }">
			<p>입력한 비밀번호가 잘 못 되었습니다.</p>
		</c:if>
	</form>

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