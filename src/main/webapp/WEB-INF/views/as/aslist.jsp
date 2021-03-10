<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<html>
<head>
	<meta charset="utf-8">
	
	<title>Home</title>

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
<body>
 <section id="container">
  <h2>교환/반품/환불 게시판</h2>
  
  <table>
   <tr><th>주문번호</th><th>분류</th><th>제목</th><th>작성자</th><th>작성일자</th></tr>
   
   <!-- 목록 시작 -->
   <c:forEach items="${asList}" var="list">
   <tr>
    <td><c:out value ="${list.order_id}"/></td>
    <td><c:out value ="${list.as_category}"/></td>
    <td>
    	<a href="./asdetail?as_no=${list.as_no}">${list.as_title}</a></td>
    	<td>${list.member_id}</td>
    <td><fmt:formatDate value="${list.as_regdate}" pattern="yyyy-MM-dd" /></td>
   </tr>
   </c:forEach>
   <!-- 목록 끝 -->
  </table>
  <div>
			<c:if test = "${pageMaker.prev}">
				<a href = "aslist${pageMaker.makeQuery(pageMaker.startPage -1)}">이전</a>
			</c:if>
			<c:forEach begin = "${pageMaker.startPage}" end ="${pageMaker.endPage}" var ="idx">
				<a href ="aslist${pageMaker.makeQuery(idx)}"> [${idx}]</a>
			</c:forEach>
			<c:if test ="${pageMaker.next && pageMaker.endPage > 0 }">
				<a href = "aslist${pageMaker.makeQuery(pageMaker.endPage +1)}">다음</a>
			</c:if>
		</div>
		 <c:if test ="${member != null }">
  	<button type="button" class="btn btn-primary form-control" onclick="location.href='../as/aswrite'">글쓰기</button>
  	</c:if>
<!--   <a href = "./aswrite">글쓰기</a> -->
 </section>
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