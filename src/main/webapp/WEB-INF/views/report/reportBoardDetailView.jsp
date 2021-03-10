<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<html>
	<head>
	 	<title>신고 게시판</title>
	 	
	 	<script src='https://code.jquery.com/jquery-3.3.1.min.js'></script>
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
	</head>
	
	<script type="text/javascript">
		
		$(document).ready(function(){
			var formObj = $("form[name='readForm']");
			
			// 수정 
			$(".modity_btn").on("click", function(){
				formObj.attr("action", "/controller/report/reportBoardModify");
				formObj.attr("method", "get");
				formObj.submit();				
			})
			
			// 삭제
			$(".delete_btn").on("click", function(){
				
				var deleteYN = confirm("삭제하시겠습니까?");
				if(deleteYN == true){
					
				formObj.attr("action", "/controller/report/reportBoardDelete");
				formObj.attr("method", "post");
				formObj.submit();
					
				}
			})
			
			// 목록
			$(".list_btn").on("click", function(){
				
				location.href = "/controller/report/reportBoardList?page=${scri.page}"
						      +"&perPageNum=${scri.perPageNum}"
						      +"&searchType=${scri.searchType}&keyword=${scri.keyword}";
			})
			
			$(".comSubmit").on("click", function(){
				if(fn_check()){
					return false;
					}
				var formObj = $("form[name='replyForm']");
				formObj.attr("action", "commentWrite");
				formObj.submit();
			});

			function fn_check(){
				var comForm = $("form[name='replyForm'] .comments").length;
				for(var i = 0; i<comForm; i++){
					if($(".comments").eq(i).val() == "" || $(".comments").eq(i).val() == null){
						alert($(".comments").eq(i).attr("title"));
						return true;
						}
					}
				}
			//댓글 수정 View
			$(".commentModify").on("click", function(){
				location.href = "/controller/report/commentModify?report_no=${read.report_no}"
								+ "&page=${scri.page}"
								+ "&perPageNum=${scri.perPageNum}"
								+ "&searchType=${scri.searchType}"
								+ "&keyword=${scri.keyword}"
								+ "&comments_no="+$(this).attr("data-comments_no");
			});
			
			//댓글 삭제 View
			$(".commentDelete").on("click", function(){
				location.href = "/controller/report/commentDelete?report_no=${read.report_no}"
					+ "&page=${scri.page}"
					+ "&perPageNum=${scri.perPageNum}"
					+ "&searchType=${scri.searchType}"
					+ "&keyword=${scri.keyword}"
					+ "&comments_no="+$(this).attr("data-comments_no");
			});
		})
		function fn_fileDown(fileNo){
			var formObj = $("form[name='readForm']");
			$("#FILE_NO").attr("value", fileNo);
			formObj.attr("action", "/controller/report/fileDown");
			formObj.submit();
		} 
		//원본 이미지 팝업
		function OnloadImg(url){
			  var img=new Image();
			  img.src=url;
			  var img_width=img.width;
			  var win_width=img.width+25;
			  var height=img.height+30;
			  var OpenWindow=window.open('','_blank', 'width='+img_width+', height='+height+', menubars=no, scrollbars=auto');
			  OpenWindow.document.write("<style>body{margin:0px;}</style><img src='"+url+"' width='"+win_width+"'>");
			 }
	</script>
	
	<body>
		<jsp:include page="../common/header.jsp"></jsp:include>
	
		<div class="container">
			<header>
				<h1>신고 게시판</h1>
			</header>
			<hr />
			
			<section id="container">
				<form name="readForm" role="form" method="post">
					<input type="hidden" id="report_no" name="report_no" value="${read.report_no}" />
					<input type="hidden" id="page" name="page" value="${scri.page}"> 
					<input type="hidden" id="perPageNum" name="perPageNum" value="${scri.perPageNum}"> 
					<input type="hidden" id="searchType" name="searchType" value="${scri.searchType}"> 
					<input type="hidden" id="keyword" name="keyword" value="${scri.keyword}"> 
					<input type="hidden" id="FILE_NO" name="FILE_NO" value=""> 
				</form>
				
				<div class="form-group">
					<label for="title" class="col-sm-2 control-label">제목</label>
					<input type="text" id="title" name="title" class="form-control" value="${read.report_title}" readonly="readonly" />
				</div>
				<div class="form-group">
					<label for="content" class="col-sm-2 control-label">내용</label>
					<textarea id="content" name="content" class="form-control" readonly="readonly"><c:out value="${read.report_content}" /></textarea>
				</div>
				<div class="form-group">
					<label for="writer" class="col-sm-2 control-label">작성자</label>
					<input type="text" id="writer" name="writer" class="form-control" value="${read.member_id}"  readonly="readonly"/>
				</div>
				<div class="form-group">
					<label for="regdate" class="col-sm-2 control-label">작성날짜</label>
					<fmt:formatDate value="${read.report_regdate}" pattern="yyyy-MM-dd" />	
				</div>
				<hr>
				<span>파일 목록</span>
				<div class="form-group" style="border: 1px solid #dbdbdb;">
					<c:forEach var="file" items="${file}">
							<a href="#" onclick="fn_fileDown('${file.FILE_NO}'); return false;">${file.ORGFILE_NAME}</a>(${file.FILE_SIZE}kb)<br>
							<img src="/controller/report/fileDown?FILE_NO=${file.FILE_NO}" width=100 height=100 onclick="OnloadImg(this.src)"/>
					</c:forEach>
				</div>
				<hr>
				<div>
					<button type="button" class="list_btn btn btn-outline-dark btn-sm">목록</button>
					<c:if test="${member.MEMBER_ID == read.member_id || member.MEMBER_VERIFY == 1}">	
					<button type="button" class="modity_btn btn btn-success btn-sm">수정</button>
					<button type="button" class="delete_btn btn btn-danger btn-sm">삭제</button>
					</c:if>
				</div>
				
				<!-- 댓글 -->
				<div id="reply">
					<ol class="comList">
						<c:forEach items="${comList}" var="comList">
							<li>
								<p>
								작성자 : ${comList.comments_writer}<br />
								작성 날짜 :  <fmt:formatDate value="${comList.comments_date}" pattern="yyyy-MM-dd" />
								</p>
								  
								<p>작성내용 : ${comList.comments_content}</p>
								<div>
								<c:if test="${member.MEMBER_ID == comList.comments_writer}">
									<button type="button" class="commentModify btn btn-success btn-sm" data-comments_no="${comList.comments_no}">수정</button>
									<button type="button" class="commentDelete btn btn-danger btn-sm" data-comments_no="${comList.comments_no}">삭제</button>
								</c:if>
								</div>
							</li>
						</c:forEach>   
					</ol>
				</div>
				
				<form name="replyForm" method="post" class="form-horizontal">
					<input type="hidden" id="report_no" name="report_no" value="${read.report_no}" />
					<input type="hidden" id="page" name="page" value="${scri.page}"> 
					<input type="hidden" id="perPageNum" name="perPageNum" value="${scri.perPageNum}"> 
					<input type="hidden" id="searchType" name="searchType" value="${scri.searchType}"> 
					<input type="hidden" id="keyword" name="keyword" value="${scri.keyword}"> 
				
				<c:if test="${member.MEMBER_ID != null}">
					<div class="form-group">
						<label for="writer" class="col-sm-2 control-label">댓글 작성자</label>
						<div class="col-sm-10">
							<input type="text" id="writer" name="comments_writer" value="${member.MEMBER_ID }" class="comments" readonly="readonly"/>
						</div>
					</div>
					
					<div class="form-group">
						<label for="content" class="col-sm-2 control-label">댓글 내용</label>
						<div class="col-sm-10">
							<input type="text" id="content" name="comments_content" class="comments" title="내용을 입력해 주세요." />
						</div>
					</div>
					
					<div class="form-group">
						<div class="col-sm-offset-2 col-sm-10">
							<button type="button" class="comSubmit btn btn-danger btn-sm">작성</button>
						</div>
					</div>
				 </c:if>	
				<c:if test="${member.MEMBER_ID == null}">
				</c:if>		
				</form>
			</section>
			<hr />
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
	<jsp:include page="../common/footer.jsp"></jsp:include>
	</body>
</html>