<%@ page language="java" contentType="text/html; charset=EUC-KR"
    pageEncoding="EUC-KR"%>
   <%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<!DOCTYPE html>
<html>
<head>
 
	<meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
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
				<button type="button"  class="btn btn-danger"onclick="location.href='${pageContext.request.contextPath}/member/myWroteList'">자유게시판</button> 
				 <button type="button" class="btn btn-danger" onclick="location.href='${pageContext.request.contextPath}/member/myReportWroteList'">신고게시판</button>
				 <button type="button" class="btn btn-danger" onclick="location.href='${pageContext.request.contextPath}/member/myQnaWroteList'">문의게시판</button>  
					<br/><br/>
					<h3>문의게시판</h3>
					<table class="table table-hover">
						<thead>
							<tr><th>번호</th><th>문의사항</th><th>제목</th><th>등록일</th><th>작성자</th></tr>
								</thead>
							<c:forEach items="${qnaList}" var = "qnaList">
							<c:if test="${member.MEMBER_ID == qnaList.member_id}">
							<tr>
								<td><c:out value="${qnaList.qna_no}" /></td>
								<td><c:out value="${qnaList.qnacate}" /></td>
								<td><a href="/controller/member/myQnaView?qna_no=${qnaList.qna_no}">${qnaList.qna_title}</a></td>
								<td><c:out value="${qnaList.qna_title}" /></td>
								<td><fmt:formatDate value="${qnaList.qna_date}" pattern="yyyy-MM-dd"/></td>
								<td><c:out value="${qnaList.member_id}" /></td>
							</tr>
							</c:if>	
						</c:forEach>
					
					</table>
					<div class="col-md-offset-3">
						 <ul class="pagination justify-content-center">
						  <c:if test="${pageMaker3.prev}">
						   <li><a href="myQnaWroteList?page=${pageMaker3.startPage - 1}" class="page-link">이전</a></li>
						  </c:if> 
						  
						  <c:forEach begin="${pageMaker3.startPage}" end="${pageMaker3.endPage}" var="idx">
						   <li><a href="myQnaWroteList?page=${idx}" class="page-link">${idx}</a></li>
						  </c:forEach>
						    
						  <c:if test="${pageMaker3.next && pageMaker3.endPage > 0}">
						   <li><a href="myQnaWroteList?page=${pageMaker3.endPage + 1}" class="page-link">다음</a></li>
						  </c:if> 
						 </ul>
					</div>
					
					</form>
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