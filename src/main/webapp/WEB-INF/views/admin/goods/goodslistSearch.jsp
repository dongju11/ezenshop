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
	
	
	<h3>상품 목록</h3>
	
 	<div id="container_box">
 		
 		<table>
 			<thead>
 				 <tr>
				   <th>썸네일</th>
				   <th>번호</th>
				   <th>이름</th>
				   <th>작성자</th>
				   <th>카테고리</th>
				   <th>가격</th>
				   <th>할인가격</th>
				   <th>수량</th>
				   <th>등록날짜</th>
			  	</tr>
 			</thead>
 		<tbody>
		 	 <c:forEach items="${list}" var="list">
			  	<tr>
				   <td><img src="${pageContext.request.contextPath}/${list.GOODS_THUMBIMG}"></td>
				   <td>${list.GOODS_NO}</td>
				   <td><a href="${pageContext.request.contextPath}/admin/goods/goodsdetail?n=${list.GOODS_NO}">${list.GOODS_NAME}</a></td>
				   <td>${list.MEMBER_ID}</td>
				   <td>${list.GOODS_CATEGORY}</td>
				   <td><fmt:formatNumber value="${list.GOODS_PRICE}" pattern="###,###,###"/></td>
				   <td><fmt:formatNumber value="${list.GOODS_DCPRICE}" pattern="###,###,###"/></td>
				   <td>${list.GOODS_STATUS}</td>
				   <td>${list.GOODS_DATE}</td>
			 	 </tr>   
		 	 </c:forEach>
 		</tbody>
		</table>

	<div class="search">
		<select name="searchType">
			<option value="n"<c:out value="${scri.searchType == null ? 'selected' : ''}"/>>------</option>
			<option value="na"<c:out value="${scri.searchType eq 'na' ? 'selected' : ''}"/>>상품이름</option>
			<option value="c"<c:out value="${scri.searchType eq 'c' ? 'selected' : ''}"/>>상품분류</option>
			<option value="d"<c:out value="${scri.searchType eq 'd' ? 'selected' : ''}"/>>상품상세내용</option>
			<option value="nad"<c:out value="${scri.searchType eq 'nad' ? 'selected' : ''}"/>>상품이름+상세내용</option>			
		</select>
		
		<input type="text" name="keyword" id="keywordInput" value="${scri.keyword}"/>
		
		
		<button id="searchBtn" class="btn btn-danger ">검색</button>
		
		<script>
			$(function(){
				$('#searchBtn').click(function(){
					self.location = "goodslistSearch"
						+ '${pageMaker.makeQuery(1)}'
						+ "&searchType="
						+ $("select option:selected").val()
						+ "&keyword="
						+ encodeURIComponent($('#keywordInput').val());
					});
				});
		</script>
	</div>



	<div>
		<ul>
			<c:if test="${pageMaker.prev}">
				<li><a href="goodslistSearch${pageMaker.makeQuery(pageMaker.startPage - 1)}">이전</a></li>			
			</c:if>
			
			<c:forEach begin="${pageMaker.startPage}" end="${pageMaker.endPage}" var="idx">
				<li><a href="goodslistSearch${pageMaker.makeQuery(idx)}">${idx}</a></li>			
			</c:forEach>
			
			<c:if test="${pageMaker.next && pageMaker.endPage > 0}">
				<li><a href="goodslistSearch${pageMaker.makeQuery(pageMaker.endPage + 1)}">다음</a></li>			
			</c:if>
		
		</ul>
	</div>


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