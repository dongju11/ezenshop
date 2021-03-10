<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<html>
<head>

	<!-- 구글 한글 적용폰트 -->
	<link rel="preconnect" href="https://fonts.gstatic.com">
	<link href="https://fonts.googleapis.com/css2?family=Jua&family=Poor+Story&display=swap" rel="stylesheet">
	<script src='https://code.jquery.com/jquery-3.3.1.min.js'></script>
	
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
</head>


<body>
	<jsp:include page="../common/header.jsp"></jsp:include>
	
	<div id="container">
		<header><h1>공지사항</h1></header>
		<section id="container">
		
			<c:if test="${msg == null }">
				<form name="writeForm" method="post" action="/controller/notice/noticeWrite" enctype="multipart/form-data">
					<div class="col-xs-10 col-sm-10">
            		<div class="col-10">
									<div class="form-group">
										<label for="title">제목</label><input type="text" id="write" name="notice_title" class="chk form-control" title="제목을 입력하세요." placeholder="제목을 입력하세요."/>
									</div>
									<div class="form-group">
										<label for="content">내용</label><textarea id="write" name="notice_content" class="chk form-control" title="내용을 입력하세요." placeholder="내용을 입력하세요."></textarea>
									</div>
									<div class="form-group">
										<label for="writer">작성자</label><input type="text" id="write" name="member_id" class="chk form-control" value="${member.MEMBER_ID}" readonly="readonly" />
									</div>
									<table>
								<tr>
									<td id="fileIndex">
									</td>
								</tr>
								<tr>
									<td>						
										<button class="write_btn btn btn-danger" type="submit">작성</button>	
										<button class="fileAdd_btn btn btn-danger" type="button">파일추가</button>	
										<span class="input-group-btn pull-right">
										<input type="button" class="btn btn-danger full-right" onclick="moveList();" value="취소">
										</span>
									</td>
								</tr>	
					</table>
				</div>
				</div>
				</form>
				</c:if>
			<c:if test="${msg == false}">
		<script type="text/javascript">
				alert("로그인후 작성가능합니다.")
				window.history.back();
	    </script>
			</c:if>
			</section>
			<hr />
		</div>
		
		<script type="text/javascript">
$(document).ready(function(){
	
	var formObj = $("form[name='writeForm']");
	$(".write_btn").on("click", function(){
		if(fn_valiChk()){
			return false;
		}
		formObj.attr("action", "/controller/notice/noticeWrite");
	});
	fn_addFile();
})

	function moveList(){
			location.href = "/controller/notice/noticeList";
		}
		
function fn_valiChk(){
	var regForm = $("form[name='writeForm'] .chk").length;
	for(var i = 0; i<regForm; i++){
		if($(".chk").eq(i).val() == "" || $(".chk").eq(i).val() == null){
			alert($(".chk").eq(i).attr("title"));
			return true;
		}
	}
}
function fn_addFile(){
	var fileIndex = 1;
	$(".fileAdd_btn").on("click", function(){
		$("#fileIndex").append("<div><input type='file' style='float:left;' name='file_"+(fileIndex++)+"'>"+"</button>"+"<button type='button' style='float:right;' id='fileDelBtn' class='btn btn-danger btn-sm'>"+"삭제"+"</button></div>");
	});
	$(document).on("click","#fileDelBtn", function(){
		$(this).parent().remove();
		
	});
}
</script>
		
		
	<!-- jQuery -->
	<script src="/controller/resources/js/jquery.min.js"></script>
	<!-- jQuery Easing -->
	<script src="/controller/resources/js/jquery.easing.1.3.js"></script>
	
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