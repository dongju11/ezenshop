<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring" %>
<html>
	<head>
	 		 	
	 	<script src='https://code.jquery.com/jquery-3.3.1.min.js'></script>
	 	<meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="//unpkg.com/bootstrap@4/dist/css/bootstrap.min.css">
	<script src='//unpkg.com/jquery@3/dist/jquery.min.js'></script>
	<script src='//unpkg.com/popper.js@1/dist/umd/popper.min.js'></script>
	<script src='//unpkg.com/bootstrap@4/dist/js/bootstrap.min.js'></script>

	 	<title>자유 게시판</title>
	</head>
	<script type="text/javascript">
		$(document).ready(function(){
			
			var formObj = $("form[name='writeForm']");
			$(".write_btn").on("click", function(){
				if(fn_valiChk()){
					return false;
				}
				formObj.attr("action", "/controller/board/boardWrite");
			});
			fn_addFile();
			
		})
		
		function moveList(){
			location.href = "/controller/board/boardList";
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
				$("#fileIndex").append("<div><input type='file' style='float:left;' name='file_"+(fileIndex++)+"'>"+"</button>"+"<button type='button' style='float:right;' id='fileDelBtn' class='btn btn-outline-secondary btn-sm'>"+"삭제"+"</button></div>");
			});
			$(document).on("click","#fileDelBtn", function(){
				$(this).parent().remove();
				
			});
		}

	</script>
	
	<body>
			<jsp:include page="../common/header.jsp" ></jsp:include>
	
		<div id="container" role="main">
			<header>
				<h1>자유 게시판</h1>
			</header>
		
			<section id="container">
			<c:if test="${msg == null }">
				<form name="writeForm" method="post" action="/controller/board/boardWrite" enctype="multipart/form-data">
					<div class="col-xs-10 col-sm-10">
            		<div class="col-10">
									<div class="form-group">
										<label for="title">제목</label><input type="text" id="write" name="fr_title" class="chk form-control" title="제목을 입력하세요." placeholder="제목을 입력하세요."/>
									</div>
									<div class="form-group">
										<label for="content">내용</label><textarea id="write" name="fr_content" class="chk form-control" title="내용을 입력하세요." placeholder="내용을 입력하세요."></textarea>
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
										<button class="write_btn btn btn-dark" type="submit">작성</button>	
										<button class="fileAdd_btn btn btn-outline-dark" type="button">파일추가</button>
										<span class="input-group-btn pull-right">
										<input type="button" class="btn btn-outline-secondary full-right" onclick="moveList();" value="취소">
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
	</body>
		<jsp:include page="../common/footer.jsp"></jsp:include>
</html>