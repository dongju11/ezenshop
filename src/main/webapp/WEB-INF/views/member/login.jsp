<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<html>
<head>
	<title>Home</title>
	   
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="//unpkg.com/bootstrap@4/dist/css/bootstrap.min.css">
	<script src='//unpkg.com/jquery@3/dist/jquery.min.js'></script>
	<script src='//unpkg.com/popper.js@1/dist/umd/popper.min.js'></script>
	<script src='//unpkg.com/bootstrap@4/dist/js/bootstrap.min.js'></script>
<script type="text/javascript" src="http://code.jquery.com/jquery-1.11.3.min.js"></script>

<script src="https://developers.kakao.com/sdk/js/kakao.js"></script>
<script src = "//developers.kakao.com/sdk/js/kakao.min.js"></script>  

<meta name="viewport" content="user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0, width=device-width"/>

	<!-- 구글 한글 적용폰트 -->
	<link rel="preconnect" href="https://fonts.gstatic.com">
	<link href="https://fonts.googleapis.com/css2?family=Jua&family=Poor+Story&display=swap" rel="stylesheet">
	
	<!-- Animate.css -->
	<link rel="stylesheet" href="/controller/resources/css/animate.css">
	<!-- Icomoon Icon Fonts-->
	<link rel="stylesheet" href="/controller/resources/css/icomoon.css">
	<!-- Bootstrap  -->
	<link rel="stylesheet" href="/controller/resources/css/bootstrap.css">
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
				<form role="form" method="post" autocomplete="off">
					<h3 style="text-align: center;">로그인 화면</h3>
					
					<div class="input_area">
						<label for="MEMBER_ID">아이디</label>
						<input type="text" class="form-control" id="MEMBER_ID" name="MEMBER_ID" placeholder="아이디" required="required" />						
					</div>
					
					<div class="input_area">
						<label for="MEMBER_PW">비밀번호</label>
						<input type="password" class="form-control" id="MEMBER_PW" name="MEMBER_PW" placeholder="비밀번호" required="required" />						
					</div>
										
					<button type="submit" class="btn btn-danger btn-block" value="회원가입">로그인</button>
					
					<c:if test="${msg == false}">
   						<p style="color:#f00;">로그인에 실패했습니다.</p>
 					</c:if>
 					
				</form>
				
				<button type="button" class="btn btn-danger btn-block" onclick="location.href='../'">메인으로 돌아가기</button>
				
				<!-- 네이버 로그인 창으로 이동 -->
				<div id="naver_id_login" style="text-align:center"><a href="${url}">
				<img src="/controller/resources/images/네이버로그인.png" width="30%"/></a></div>
				<br>
				<!-- 카카오 로그인 창으로 이동 -->
				<center>
				 <a href="https://kauth.kakao.com/oauth/authorize?client_id=d8575f6840422aad90c30fa099c54912&redirect_uri=http://localhost:8085/controller/member/kakaologin&response_type=code">
				    <img src="/controller/resources/images/카카오로그인.jpg" width="30%"/></a>
				</center>
				
				
				<div class="col-md-6 button1  mt-2">
					<button type="button" class="btn btn-danger btn-block"
						onclick="location.href='find_Id'">아이디 찾기</button>
				</div>
				<div class="col-md-6 button2  mt-2">
					<button type="button" class="btn btn-danger btn-block"
						onclick="location.href='find_Pw'">비밀번호 찾기</button>
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