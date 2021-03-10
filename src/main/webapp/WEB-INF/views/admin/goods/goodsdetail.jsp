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
			.oriImg { width:500px; height:auto;}
			.thumbImg {}
		</style>
		
</head>
<body>
<jsp:include page="../common/adminHeader.jsp"></jsp:include>
	
 	<div class="container">	
 	<h1 class="text-center">상품 조회</h1>
 		
		<form role="form" method="post" autocomplete="off">
	 		
	 		<input type="hidden" name="n" value="${goods.GOODS_NO}" />
	 		
	 		<div class="form-row">
	 		 	<label>1차 분류</label>
		 			<span class="category1"></span>
		 				 
		   		 <label>2차 분류</label>
		 			<span class="category2">${goods.GOODS_CATEGORY}</span>
		 	</div>
		 	
			<div class="form-row">
		 		<div class="form-group col-md-2">
 					<label for="GOODS_NAME">상품명</label>
 					<span class="badge badge-primary">${goods.GOODS_NAME}</span>
		 		</div>
		 
		    	<div class="form-group col-md-2">
 					<label for="GOODS_PRICE">상품가격</label>
 					<span>${goods.GOODS_PRICE}</span>
		   		</div> 
		 
		  		<div class="form-group col-md-2">
 					<label for="GOODS_DCPRICE">상품할인가격</label>
 					<span><fmt:formatNumber value="${goods.GOODS_DCPRICE}" pattern="###,###,###"/></span>
		 		</div> 
		 	</div>
		 
		   <div class="form-row">
		  		<div class="form-group col-md-2">
 					<label for="GOODS_SIMPLE">간략설명</label>
 					<div class="GOODS_SIMPLE">${goods.GOODS_SIMPLE}</div>
		 		</div>  
		 
				 <div class="form-group col-md-2">
 					<label for="GOODS_BRAND">브랜드</label>
 					<span>${goods.GOODS_BRAND}</span>
				 </div>  
		 
				 <div class="form-group col-md-2">
 					<label for="GOODS_SHIPPING">배송비</label>
 					<span>${goods.GOODS_SHIPPING}</span>
		 		</div>  
		 
				 <div class="form-group col-md-2">
 					<label for="GOODS_STATUS">상태</label>
 					<span>${goods.GOODS_STATUS}</span>
		 		</div>
			 </div>
		 
		 <div class="inputArea">
 			<label for="GOODS_DETAIL">상세설명</label>
 			<div class="GOODS_DETAIL">${goods.GOODS_DETAIL}</div>
		 </div>  
		 
		 <div class="inputArea">
		 	<label for="GOODS_IMAGE">이미지</label>
		 	<p></p>
		 	<img src="${pageContext.request.contextPath}/${goods.GOODS_IMAGE}" class="oriImg"/>
		 	
		 	<p>썸네일</p>
		 	<img src="${pageContext.request.contextPath}/${goods.GOODS_THUMBIMG}" class="thumbImg"/>
		 </div>  
		 

		<div class="inputArea">
			<button type="button" id="goodsmodify_Btn" class="btn btn-dark btn-block">수정</button>
			<button type="button" id="goodsdelete_Btn" class="btn btn-danger btn-block">삭제</button>
			<script>
				var formObj = $("form[role='form']");
				  
				  $("#goodsmodify_Btn").click(function(){
				   formObj.attr("action", "/controller/goods/goodsmodify");
				   formObj.attr("method", "get")
				   formObj.submit();
				  });
				  
				  $("#goodsdelete_Btn").click(function(){ 

					  var con = confirm("정말로 삭제하시겠습니까?");
					  if(con) {   
				   formObj.attr("action", "/controller/goods/goodsdelete");
				   formObj.submit();
					  }
				  });
			</script>
			
			
		</div>
	 
	</form>
	
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