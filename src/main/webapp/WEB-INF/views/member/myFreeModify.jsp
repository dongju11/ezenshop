<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<html>
	<head>
	 	
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
	
	 	<title>자유 게시판</title>
	</head>
	<script type="text/javascript">
		$(document).ready(function(){
			var formObj = $("form[name='updateForm']");
			
			$(document).on("click","#fileDel", function(){
				$(this).parent().remove();
			})
			
			fn_addFile();
			
			$(".cancel_btn").on("click", function(){
				event.preventDefault();
				location.href = "/controller/member/myFreeView?fr_no=${modify.fr_no}";
			})
			
			$(".update_btn").on("click", function(){
				if(fn_valiChk()){
					return false;
				}
				formObj.attr("action", "/controller/member/myFreeModify");
				formObj.attr("method", "post");
				formObj.submit();
			})
		})
			
		function fn_valiChk(){
			var updateForm = $("form[name='updateForm'] .chk").length;
			for(var i = 0; i<updateForm; i++){
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
 		var fileNoArry = new Array();
 		var fileNameArry = new Array();
 		function fn_del(value, name){
 			
 			fileNoArry.push(value);
 			fileNameArry.push(name);
 			$("#fileNoDel").attr("value", fileNoArry);
 			$("#fileNameDel").attr("value", fileNameArry);
 		}
	</script>
	<body>
		<jsp:include page="../common/header.jsp"></jsp:include>
	
		<div id="container" role="main">
			<header>
				<h1>자유 게시판</h1>
			</header>
			
			<section id="container">
				<form name="updateForm" role="form" method="post" action="/controller/member/myFreeModify" enctype="multipart/form-data">
					<input type="hidden" name="fr_no" value="${modify.fr_no}" readonly="readonly"/>
					<input type="hidden" id="fileNoDel" name="fileNoDel[]" value=""> 
					<input type="hidden" id="fileNameDel" name="fileNameDel[]" value=""> 
					<div class="col-xs-10 col-sm-10">
            			<div class="col-10">
            					<div class="form-group">
									<label for="title">제목</label><input type="text" id="title" name="fr_title" value="${modify.fr_title}" class="chk form-control" title="제목을 입력하세요."/>
								</div>
								<div class="form-group">	
									<label for="content">내용</label><textarea id="content" name="fr_content" class="chk form-control" title="내용을 입력하세요."><c:out value="${modify.fr_content}" /></textarea>
								</div>
								<div class="form-group">
									<label for="writer">작성자</label><input type="text" id="writer" name="member_id" value="${modify.member_id}" class="form-control" readonly="readonly"/>
								</div>
								<div class="form-group">
									<label for="regdate">작성날짜</label>
									<fmt:formatDate value="${modify.fr_date}" pattern="yyyy-MM-dd"/>					
								</div>
							<table>
							<tr>
								<td id="fileIndex">
									<c:forEach var="file" items="${file}" varStatus="var">
									<div class="col-sm-10">
										<input type="hidden" id="FILE_NO" name="FILE_NO_${var.index}" value="${file.FILE_NO }">
										<input type="hidden" id="FILE_NAME" name="FILE_NAME" value="FILE_NO_${var.index}">
										<a href="#" id="fileName" onclick="return false;">${file.ORGFILE_NAME}</a>(${file.FILE_SIZE}kb)
										<button id="fileDel" onclick="fn_del('${file.FILE_NO}','FILE_NO_${var.index}');" type="button" class="btn btn-danger btn-sm" style="float: right;">삭제</button>
									</div>
									</c:forEach>
								</td>
							</tr>
					</table>
					</div>
					</div>
					<div class="col-sm-10">
						<button type="button" class="update_btn btn btn-danger">저장</button>
						<button type="button" class="cancel_btn btn btn-danger">취소</button>
						<button type="button" class="fileAdd_btn  btn btn-danger">파일추가</button>
					</div>
				</form>
			</section>
			<hr />
		</div>


	
	</body>
</html>