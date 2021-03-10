<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
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
		<style>
#container_box table td { width:100px; }
</style>	
</head>
<body>
<jsp:include page="../common/adminHeader.jsp"></jsp:include>
	
 	<div id="container_box">
 		<table>
 <thead>
  <tr>
   <th>썸네일</th>
   <th>번호</th>
   <th>이름</th>
   <th>카테고리</th>
   <th>가격</th>
   <th>할인가격</th>
   <th>수량</th>
   <th>등록날짜</th>
  </tr>
 </thead>
 <tbody>
  <c:forEach items="${goodslist}" var="goodslist">
  <tr>
  	<td><img src="${pageContext.request.contextPath}/${goodslist.GOODS_THUMBIMG}"></td>
   <td>${goodslist.GOODS_NO}</td>
   <td><a href="${pageContext.request.contextPath}/admin/goods/goodsdetail?n=${goodslist.GOODS_NO}">${goodslist.GOODS_NAME}</a></td>
   <td>${goodslist.CATENAME}</td>
  	<td><fmt:formatNumber value="${goodslist.GOODS_PRICE}" pattern="###,###,###"/></td>
    <td><fmt:formatNumber value="${goodslist.GOODS_DCPRICE}" pattern="###,###,###"/></td>
   <td>${goodslist.GOODS_STATUS}</td>
   <td>${goodslist.GOODS_DATE}</td>
  </tr>   
  </c:forEach>
 </tbody>
</table>
 	</div>
<jsp:include page="../common/adminFooter.jsp"></jsp:include>
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