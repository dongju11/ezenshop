<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
    <%@taglib uri ="http://java.sun.com/jsp/jstl/core" prefix="c" %>
    <%@ taglib prefix ="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="//unpkg.com/bootstrap@4/dist/css/bootstrap.min.css">
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
<title>공지사항</title>
<script src = 'https://code.jquery.com/jquery-3.3.1.min.js'></script>
</head>
<body>
<jsp:include page="../common/header.jsp"></jsp:include>
<div id ="root">
 <header>
  <h1>공지사항</h1>
 </header>
	<section id ="container">
		<form role ="form" method ="post" autocomplete="off">
			<p>
			<label for ="notice_no">글번호 </label><input type ="text" class="form-control" id ="notice_no" name ="notice_no" value="${delete}" readonly="readonly"/>
			</p>
			
			<p>정말로 삭제하시겠습니까?</p>
			
			<p>
			<button type ="submit"> 예, 삭제합니다</button><br>
			<button id ="cancel_btn">아니오, 삭제하지 않습니다</button>
			
			<script>
				var formObj = $("form[role='form']");

				$("#cancel_btn").click(function(){
					self.location = "/notice/noticeDetail?notice_no=${delete}"
						   + "&page=${scri.page}"
						   + "&perPageNum=${scri.perPageNum}"
						   + "&searchType=${scri.searchType}"
						   + "&keyword=${scri.keyword}";
					});
	
			</script>
			</p>
			</form>
	</section>
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
</body>
</html>