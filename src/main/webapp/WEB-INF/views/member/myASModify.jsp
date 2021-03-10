<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<html>
<head>
<title>Home</title>
<meta charset="utf-8">
<meta name="viewport"
	content="width=device-width, initial-scale=1, shrink-to-fit=no">
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
	<jsp:include page="../common/header.jsp"></jsp:include>

	<section id="container">

		<form role="form" method="post" autocomplete="off">
			<h2>교환/반품/환불</h2>
			<p>
				<label for="as_no"></label><input type="hidden" id="no"
					name="as_no" value="${modify.as_no}" />
			</p>

			<p>
				<label for="order_no">주문번호</label><input type="text" id="order_no"
					name="order_no" value="${modify.order_no}"/>
			</p>
			<p>
				<label for="as_writer">작성자</label><input type="text" id="writer"
					name="as_writer" value ="${member.MEMBER_ID}"/>
			</p>
			<p>
				<label for="as_title">제목</label><input type="text" id="title"
					name="as_title" value="${modify.as_title}"/>
			</p>
			<p>
			<label for="as_category">분류</label> <select id="category"
				name="as_category">
				<option title="">사유선택</option>
				<option value="교환">교환</option>
				<option value="환불">환불</option>
				<option value="반품">반품</option>
			</select>
			</p>

			<p>
				<label for="as_content">사유</label><input type="text" id="content"
					name="as_content" value="${modify.as_content}" />
			</p>

			<p>
	
			 <label for="as_account">환불 계좌</label>
			 <select>
					<option title="">은행명</option>
					<option value="국민">국민</option>
					<option value="신한">신한</option>
					<option value="농협">농협</option>
			 </select>
			 <input type="text"
					id="account" name="as_account" value="${modify.as_account}"/>
			</p>
			<p>
			<label>작성 날짜</label> <span><fmt:formatDate
					value="${modify.as_regdate}" pattern="yyyy-MM-dd" /></span>
			</p>
			<p>
				<button type="submit">수정</button>
				<button id="cancel_btn">취소</button>

				<script>
		var formObj = $("form[role='form']");
		//취소 버튼
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
	<jsp:include page="../common/footer.jsp"></jsp:include>
</body>
</html>