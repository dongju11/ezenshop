<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<html>
<head>
<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<title>회원 탈퇴</title>
	
	<meta name="viewport" content="width=device-width, initial-scale=1">
	
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
	<script src='https://code.jquery.com/jquery-3.3.1.min.js'></script>	 
<style>
	
	 	table.type03 {
  border-collapse: collapse;
  text-align: left;
  line-height: 1.5;
  border-top: 1px solid #ccc;
  border-left: 3px solid #369;
  margin : 20px 10px;
}
table.type03 th {
  width: 147px;
  padding: 10px;
  font-weight: bold;
  vertical-align: top;
  color: #153d73;
  border-right: 1px solid #ccc;
  border-bottom: 1px solid #ccc;

}
table.type03 td {
  width: 349px;
  padding: 10px;
  vertical-align: top;
  border-right: 1px solid #ccc;
  border-bottom: 1px solid #ccc;
}
	 	</style>
<script type="text/javascript">
	// 비밀번호 미입력시 경고창
	function checkValue() {
		if (!document.deleteform.password.value) {
			alert("비밀번호를 입력하지 않았습니다.");
			return false;
		}
	}
</script>
</head>

<body>
	<jsp:include page="../common/footer.jsp"></jsp:include>

	<form role="form" method="post" autocomplete="off">

		<h3 style="text-align: center;">회원정보 탈퇴</h3>
		<p>
			<label for="MEMBER_ID">아이디</label> <input type="text" id="MEMBER_ID"
				name="MEMBER_ID" value="${member.MEMBER_ID}" />
		</p>

		<p>
			<label for="MEMBER_PW">비밀번호</label> <input type="password"
				id="MEMBER_PW" name="MEMBER_PW" />
		</p>
		<p>
			<button type="submit">회원정보 탈퇴</button>
		</p>

		<p>
			<button type="button" onclick="location.href='mypage'">취소</button>
		</p>


		<c:if test="${msg == false }">
			<p>입력한 비밀번호가 잘 못 되었습니다.</p>
		</c:if>



	</form>
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