<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<html>
	<head>
		<title>자유 게시판</title>
<script src='https://code.jquery.com/jquery-3.3.1.min.js'></script>	
     <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    
	<!-- Bootstrap  -->
	<link rel="stylesheet" href="/controller/resources/css/bootstrap.css">
	 	<script src='https://code.jquery.com/jquery-3.3.1.min.js'></script>
	 	<!-- Theme style  -->
	<link rel="stylesheet" href="/controller/resources/css/style.css">
	</head>
	
	<script type="text/javascript">
	function moveWrite(){
		location.href = "/controller/board/boardWrite";
		}
	</script>
	
	<body>
	<jsp:include page="../common/header.jsp"></jsp:include>
		<div class="container">
			<header>
				<h1>자유 게시판</h1>
			</header>
			
			<section id="container">
				<form role="form" method="get">
					<table class="table table-hover">
						<thead>
							<tr><th>번호</th><th>제목</th><th>작성자</th><th>등록일</th><th>조회수</th></tr>
						</thead>
						
						<c:forEach items="${list}" var = "list">
							<tr>
								<td><c:out value="${list.fr_no}" /></td>
								<td>
									<a href="/controller/board/boardDetail?fr_no=${list.fr_no}&page=${scri.page}&perPageNum=${scri.perPageNum}&searchType=${scri.searchType}&keyword=${scri.keyword}"><c:out value="${list.fr_title}" /></a>
								</td>
								<td><c:out value="${list.member_id}" /></td>
								<td><fmt:formatDate value="${list.fr_date}" pattern="yyyy-MM-dd"/></td>
								<td><c:out value="${list.fr_count}" /></td>
							</tr>
						</c:forEach>
						
					</table>
					<div align="right">
						<button type="button" onclick="moveWrite();" class="btn btn-danger btn-sm">글쓰기</button>
					</div>	
					<br/><br/>
					<div class="search row">
						<div class="col-xs-2 col-sm-2">
							<select name="searchType" class="form-control">
								<option value="n"<c:out value="${scri.searchType == null ? 'selected' : ''}"/>>-----</option>
								<option value="t"<c:out value="${scri.searchType eq 't' ? 'selected' : ''}"/>>제목</option>
								<option value="c"<c:out value="${scri.searchType eq 'c' ? 'selected' : ''}"/>>내용</option>
								<option value="w"<c:out value="${scri.searchType eq 'w' ? 'selected' : ''}"/>>작성자</option>
								<option value="tc"<c:out value="${scri.searchType eq 'tc' ? 'selected' : ''}"/>>제목+내용</option>
							</select>
						</div>
						 
						<div class="col-xs-10 col-sm-10">
							<div class="input-group">
								<input type="text" name="keyword" id="keywordInput" value="${scri.keyword}" class="form-control"/>
								<span class="input-group-btn">
									<button id="searchBtn" type="button" class="btn btn-danger">검색</button> 	
								</span>
							</div>
						</div>
						 
						<script>
							 $(function(){
								 $('#searchBtn').click(function() {
									 self.location = "boardList" + '${pageMaker.makeQuery(1)}' + "&searchType=" + $("select option:selected").val() + "&keyword=" + encodeURIComponent($('#keywordInput').val());
								 });
							 });   
						</script>
					</div>
					<div class="col-md-offset-3">
						<ul class="pagination justify-content-center">
							<c:if test="${pageMaker.prev}">
								<li class="page-item"><a href="boardList${pageMaker.makeSearch(pageMaker.startPage - 1)}" class="page-link">이전</a></li>
							</c:if> 
							
							<c:forEach begin="${pageMaker.startPage}" end="${pageMaker.endPage}" var="idx">
								<li class="page-item" <c:out value="${pageMaker.cri.page == idx ? 'class=info' : ''}" />>
								<a href="boardList${pageMaker.makeSearch(idx)}" class="page-link">${idx}</a></li>
							</c:forEach>
							
							<c:if test="${pageMaker.next && pageMaker.endPage > 0}">
								<li class="page-item" ><a href="boardList${pageMaker.makeSearch(pageMaker.endPage + 1)}" class="page-link">다음</a></li>
							</c:if> 
						</ul>
					</div>
				</form>
			</section>
		</div>
	</body>
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
</html>