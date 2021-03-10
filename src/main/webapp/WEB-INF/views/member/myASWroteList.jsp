<%@ page language="java" contentType="text/html; charset=EUC-KR"
	pageEncoding="EUC-KR"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
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

<title>내 작성내역 조회</title>
<style>
.tablinks.active {
	color: #000;
	background-color: #fff;
}
</style>
</head>

<body>
	<jsp:include page="../common/header.jsp"></jsp:include>

	<div class="container">
		<header>
			<h1>내 작성내역 조회</h1>
		</header>
		<hr />
		<section id="container">
			<c:if test="${msg != 'login_error'}">
				<form role="form" method="get">
					<button type="button" class="tablinks"
						onclick="location.href='${pageContext.request.contextPath}/member/myWroteList'">자유게시판</button>
					<button type="button" class="tablinks"
						onclick="location.href='${pageContext.request.contextPath}/member/myReportWroteList'">신고게시판</button>
					<button type="button" class="tablinks"
						onclick="location.href='${pageContext.request.contextPath}/member/myQnaWroteList'">문의게시판</button>
					<button type="button" class="tablinks active" 
						onclick="location.href='${pageContext.request.contextPath}/member/myASWroteList'">교환/반품/환불 게시판</button>
					<button type="button" class="tablinks" onclick="location.href='${pageContext.request.contextPath}/goods/mygoodsList'">상품게시판</button>
					<button type="button" class="tablinks" onclick="location.href='${pageContext.request.contextPath}/shop/myorderList'">주문게시판</button>   	
					<br />
					<br />
					<table class="table table-hover">
						<tr>교환/반품/환불 게시판
						</tr>
						<thead>
							<tr>
								<th>주문번호</th>
								<th>분류</th>
								<th>제목</th>
								<th>작성자</th>
								<th>등록일</th>
							</tr>
						</thead>
						<c:forEach items="${myASList}" var="myASList">
							<c:if test="${member.MEMBER_ID == myASList.member_id}">
								<tr>
									<td><c:out value="${myASList.order_no}" /></td>
									<td><c:out value="${myASList.as_category}" /></td>
									<td><a href="./myASView?as_no=${myASList.as_no}">${myASList.as_title}</a></td>
									<td><c:out value="${myASList.member_id}" /></td>
									<td><fmt:formatDate value="${myASList.as_regdate}"
											pattern="yyyy-MM-dd" /></td>
									
								</tr>
							</c:if>
						</c:forEach>
					</table>
					<div>
						<c:if test="${pageMaker4.prev}">
							<a
								href="myASWroteList?${pageMaker4.makeQuery(pageMaker4.startPage -1)}">이전</a>
						</c:if>
						<c:forEach begin="${pageMaker4.startPage}"
							end="${pageMaker4.endPage}" var="idx">
							<a href="myASWroteList?${pageMaker4.makeQuery(idx)}">
								[${idx}]</a>
						</c:forEach>
						<c:if test="${pageMaker4.next && pageMaker4.endPage > 0 }">
							<a
								href="myASWroteList?${pageMaker4.makeQuery(pageMaker.endPage +1)}">다음</a>
						</c:if>
					</div>
				</form>
			</c:if>
			<c:if test="${msg == 'login_error'}">
				<p>로그인이 필요합니다</p>
				<p>
					<a href="${pageContext.request.contextPath}">홈으로</a>
			</c:if>
		</section>
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