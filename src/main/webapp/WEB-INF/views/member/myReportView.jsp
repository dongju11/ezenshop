<%@ page language="java" contentType="text/html; charset=EUC-KR"
    pageEncoding="EUC-KR"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>    
<!DOCTYPE html>
<html>
<head>
<title>신고 게시판</title>
	 	

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
				formObj.attr("action", "/controller/member/myReportModify");
				formObj.attr("method", "get");
				formObj.submit();				
			})
			
			// 삭제
			$(".delete_btn").on("click", function(){
				
				var deleteYN = confirm("삭제하시겠습니까?");
				if(deleteYN == true){
					
				formObj.attr("action", "/controller/member/myReportRemove");
				formObj.attr("method", "post");
				formObj.submit();
					
				}
			$("a[name='file']").on("click",function(e){
		         e.preventDefault();
		         fn_fileDownload($(this));
		      })	

			})
			
			// 목록
			$(".list_btn").on("click", function(){
				
				location.href = "/controller/member/myWroteList?";
			})

			
		})
			function fn_fileDown(fileNo){
			var formObj = $("form[name='readForm']");
			$("#FILE_NO").attr("value", fileNo);
			formObj.attr("action", "/controller/report/fileDown");
			formObj.submit();
		}
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
					<input type="hidden" id="report_no" name="report_no" value="${boardRead.report_no}" />
					<input type="hidden" id="FILE_NO" name="FILE_NO" value=""> 
				</form>
				
				<div class="form-group">
					<label for="title" class="col-sm-2 control-label">제목</label>
					<input type="text" id="title" name="title" class="form-control" value="${boardRead.report_title}" readonly="readonly" />
				</div>
				<div class="form-group">
					<label for="content" class="col-sm-2 control-label">내용</label>
					<textarea id="content" name="content" class="form-control" readonly="readonly"><c:out value="${boardRead.report_content}" /></textarea>
				</div>
				<div class="form-group">
					<label for="writer" class="col-sm-2 control-label">작성자</label>
					<input type="text" id="writer" name="writer" class="form-control" value="${boardRead.member_id}"  readonly="readonly"/>
				</div>
				<div class="form-group">
					<label for="regdate" class="col-sm-2 control-label">작성날짜</label>
					<fmt:formatDate value="${boardRead.report_regdate}" pattern="yyyy-MM-dd" />	
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
					<button type="button" class="list_btn btn btn-outline-dark btn-sm btn btn-primary">목록</button>	
					<button type="button" class="modity_btn btn btn-outline-info btn-sm btn btn-warning">수정</button>
					<button type="button" class="delete_btn btn  btn-sm btn btn-info">삭제</button>
				</div>
	</section>
			<hr />
		</div>			

</body>
</html>