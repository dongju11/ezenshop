<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<html>
<head>
	<title>Home</title>
	   
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    
    
    
    
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


<script src="https://developers.kakao.com/sdk/js/kakao.js"></script>
<script src = "//developers.kakao.com/sdk/js/kakao.min.js"></script>  

<meta name="viewport" content="user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0, width=device-width"/>

	<!-- 구글 한글 적용폰트 -->
	<link rel="preconnect" href="https://fonts.gstatic.com">
	<link href="https://fonts.googleapis.com/css2?family=Jua&family=Poor+Story&display=swap" rel="stylesheet">
	
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
	<title>list</title>
	
	
	<style>
	
	.allCheck { float:left; width:200px; }
.allCheck input { width:16px; height:16px; }
.allCheck label { margin-left:10px; }
.delBtn { float:right; width:300px; text-align:right; }
.delBtn button { font-size:18px; padding:5px 10px; border:1px solid #eee; background:#eee;}

.checkBox { float:left; width:30px; }
.checkBox input { width:16px; height:16px; }
	
	
	
	section#content ul li { margin:10px 0; }
 section#content ul li img { width:250px; height:250px; }
 section#content ul li::after { content:""; display:block; clear:both; }
 section#content div.GOODS_THUMBIMG { float:left; width:200px; }
 section#content div.GOODSINFO { float: right; width:calc(100% - 400px); padding-top: 40px ;}
 section#content div.GOODSINFO { font-size:15px; line-height:2; }
 section#content div.GOODSINFO span { display:inline-block; width:150px; font-weight:bold;}
 section#content div.GOODSINFO .delete { float: right; }
 section#content div.GOODSINFO .delete button { font-size:18px;
            padding:5px 10px; border:1px solid #eee; background:#eee; }
		
		
		.listResult { padding:20px; background:#eee; }
.listResult .sum { float:left; width:45%; font-size:22px; }

.listResult .orderOpne { float:right; width:45%; text-align:right; }
.listResult .orderOpne button { font-size:18px; padding:5px 10px; border:1px solid #999; background:#fff;}
.listResult::after { content:""; display:block; clear:both; }
		
		.orderInfo { border:5px solid #eee; padding:20px; display:none; }
		.orderInfo .inputArea { margin:10px 0; }
		.orderInfo .inputArea label { display:inline-block; width:120px; margin-right:10px; }
		.orderInfo .inputArea input { font-size:14px; padding:5px; }


.orderInfo .inputArea:last-child { margin-top:30px; }
.orderInfo .inputArea button { font-size:20px; border:2px solid #ccc; padding:5px 10px; background:#fff; margin-right:20px;}
		
	</style>
	
</head>
<body>
<jsp:include page="../common/header.jsp"></jsp:include>
<div id="root">
	

	<h3>찜목록</h3>
	<section id="container">
		<div id="container_box">
			<section id="content">
				<ul>
					<li>
						<div class="allCheck">
							<input type="checkbox" name="allCheck" id="allCheck" /><label for="allCheck">모두 선택</label>
							
							<script>
								$("#allCheck").click(function(){
									var chk = $("#allCheck").prop("checked");
									if(chk) {
										$(".chBox").prop("checked", true);
									} else {
										$(".chBox").prop("checked", false);
									}
								});
							</script>
						</div>
						
						<div class="delBtn">
							<button type="button" class="selectDelete_btn btn btn-danger">선택 삭제</button>
							
							<script>
							$(".selectDelete_btn").click(function(){
								var confirm_val = confirm("정말 삭제하시겠습니까?");

								if(confirm_val) {
									var checkArr = new Array();

									$("input[class='chBox']:checked").each(function(){
										checkArr.push($(this).attr("data-JJIM_NUM"));
									});

									$.ajax({
										url : "/controller/shop/deleteJjim",
										type : "post",
										data : { chbox : checkArr },
										success : function(result){

											if(result ==1){
												location.href = "/controller/shop/jjimList";
											} else {
												alert("삭제 실패");		
											}
										}
									});
								}
							});
							</script>
							
						</div>
					</li>
					
					<c:set var="sum" value="0" />
				
					<c:forEach items="${jjimList}" var="jjimList">
					<li>
						<div class="checkBox">
							<input type="checkbox" name="chBox" class="chBox" data-JJIM_NUM="${jjimList.JJIM_NUM}" />
							
							<script>
								$(".chBox").click(function(){
									$("#allCheck").prop("checked", false);
								});
							</script>
						</div>
						
						<div class="GOODS_THUMBIMG">
							<img src="${pageContext.request.contextPath}/${jjimList.GOODS_THUMBIMG}" />
						</div>
							
						<div class="GOODSINFO">
							<p>
								<span>상품명 :</span><a href="${pageContext.request.contextPath}/shop/view?n=${jjimList.GOODS_NO}">${jjimList.GOODS_NAME} </a>
								<br />
								<span>가격 :</span>
									<fmt:formatNumber pattern="###,###,###" value="${jjimList.GOODS_PRICE}" />원<br />
								<span style="color:deepskyblue">할인 가격 :</span>
									<fmt:formatNumber pattern="###,###,###" value="${jjimList.GOODS_DCPRICE}" />원<br />
								<span>브랜드 :</span>${jjimList.GOODS_BRAND}<br />
								<span>배송비 :</span>${jjimList.GOODS_SHIPPING}원<br />
								<span style="color:limegreen">배송비 포함 가격 :</span>
								<fmt:formatNumber pattern="###,###,###" value="${jjimList.GOODS_DCPRICE + jjimList.GOODS_SHIPPING}" /> 원 <br />
								<span>재고 :</span> <fmt:formatNumber pattern="###,###,###" value="${jjimList.GOODS_STATUS}" /> 개 <br/>	
							</p>
							
							<div class="delete">
								<button type="button" class="delete_${jjimList.JJIM_NUM}_btn btn btn-danger" data-JJIM_NUM="${jjimList.JJIM_NUM}">삭제</button>
								<script>
									$(".delete_${jjimList.JJIM_NUM}_btn").click(function(){
										var confirm_val = confirm("정말 삭제하시겠습니까?");

										if(confirm_val) {
											var checkArr = new Array();

											checkArr.push($(this).attr("data-JJIM_NUM"));

											$.ajax({
												url : "/controller/shop/deleteJjim",
												type : "post",
												data : { chbox : checkArr },
												success : function(result) {

													if(result == 1) {
														location.href = "/controller/shop/jjimList";
														
														} else {
															alert("삭제 실패");
														}

													}


												});
												
											}
										});
								</script>
							</div>
						</div>
					</li>
					
					</c:forEach>
				
				</ul>
				
			</section>
			
			
		</div>
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
