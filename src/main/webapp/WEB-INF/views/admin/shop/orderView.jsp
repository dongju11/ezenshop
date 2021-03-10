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
	<title>list</title>
	
	
	
	<style>
	
		body { margin:0; padding:0; font-family:'맑은 고딕', verdana; }
		a { color:#05f; text-decoration:none; }
		a:hover { text-decoration:underline; }
		
		h1, h2, h3, h4, h5, h6 { margin:0; padding:0; }
		ul, lo, li { margin:0; padding:0; list-style:none; }
	
		/* ---------- */
		
		div#root { width:900px; margin:0 auto; }
		header#header {}
			section#container { }
			section#content { float:right; width:700px; }
			aside#aside { float:left; width:180px; }
			section#container::after { content:""; display:block; clear:both; }	
		footer#footer { background:#eee; padding:20px; }
		
		/* ---------- */
		
		header#header div#header_box { text-align:center; padding:30px 0; }
		header#header div#header_box h1 { font-size:50px; }
		header#header div#header_box h1 a { color:#000; }
		
		nav#nav div#nav_box { font-size:14px; padding:10px; text-align:right; }
		nav#nav div#nav_box li { display:inline-block; margin:0 10px; }
		nav#nav div#nav_box li a { color:#333; }
		
		section#container { }
		
		aside#aside h3 { font-size:22px; margin-bottom:20px; text-align:center; }
		aside#aside li { font-size:16px; text-align:center; }
		aside#aside li a { color:#000; display:block; padding:10px 0; }
		aside#aside li a:hover { text-decoration:none; background:#eee; }
		
		aside#aside li { position:relative; }
		aside#aside li:hover { background:#eee; } 		
		aside#aside li > ul.low { display:none; position:absolute; top:0; left:180px;  }
		aside#aside li:hover > ul.low { display:block; }
		aside#aside li:hover > ul.low li a { background:#eee; border:1px solid #eee; }
		aside#aside li:hover > ul.low li a:hover { background:#fff;}
		aside#aside li > ul.low li { width:180px; }
		
		footer#footer { margin-top:100px; border-radius:50px 50px 0 0; }
		footer#footer div#footer_box { padding:0 20px; }
		
		section#content ul li { display:inline-block; margin:10px; }
 		section#content div.GOODS_THUMB img { width:200px; height:200px; }
 		section#content div.GOODS_NAME { padding:10px 0; text-align:center; }
 		section#content div.GOODS_NAME a { color:#000; }
 		section#content div.GOODS_SIMPLE { padding:12px 0; text-align:center; }
 		section#content div.GOODS_SIMPLE a { color:#000; }
 		section#content div.GOODS_PRICE { padding:14px 0; text-align:center; }
 		section#content div.GOODS_PRICE a { color:#000; }
 		
 		 .orderInfo { border:5px solid #eee; padding:10px 20px; margin:20px 0;}
 .orderInfo span { font-size:20px; font-weight:bold; display:inline-block; width:90px; }
 
 .orderView li { margin-bottom:20px; padding-bottom:20px; border-bottom:1px solid #999; }
 .orderView li::after { content:""; display:block; clear:both; }
 
 .thumb { float:left; width:200px; }
 .thumb img { width:200px; height:200px; }
 .gdsInfo { float:right; width:calc(100% - 220px); line-height:2; }
 .gdsInfo span { font-size:20px; font-weight:bold; display:inline-block; width:100px; margin-right:10px; }
 
 .deliveryChange { text-align:right; }
.delivery1_btn,
.delivery2_btn { font-size:16px; background:#fff; border:1px solid #999; margin-left:10px; }
		
	</style>
	
</head>
<body>
<jsp:include page="../common/adminHeader.jsp"></jsp:include>
<div id="root">
	

	
	<section id="container">
		<div id="container_box">
		
			<div class="orderInfo">
				  <c:forEach items="${orderView}" var="orderView" varStatus="status">
				  
				  <c:if test="${status.first}">
				   <p><span>주문번호</span> ${orderView.ORDER_ID}</p>
				   <p><span>주문자</span>${orderView.MEMBER_ID}</p>
				   <p><span>수령인</span>${orderView.ORDER_REC}</p>
				   <p><span>주소</span>(${orderView.MEMBER_ADDR})</p>
				   <p><span>가격</span><fmt:formatNumber pattern="###,###,###" value="${orderView.ORDER_AMOUNT}" /> 원</p>
				   <p><span>상태</span>${orderView.ORDER_DELIVERY}</p>
				   
				   <div class="deliveryChange">
				   		<form role="form" method="post" class="deliveryForm">
				   		
				   			<input type="hidden" name="ORDER_ID" value="${orderView.ORDER_ID}" />
				   			<input type="hidden" name="ORDER_DELIVERY" class="ORDER_DELIVERY" value="" />
				   			
				   		<button type="button" class="delivery1_btn btn btn-danger">배송중</button>
				   		<button type="button" class="delivery2_btn btn btn-success" >배송 완료</button>
				   		
				   		<script>
							$(".delivery1_btn").click(function(){
								$(".ORDER_DELIVERY").val("배송 중");
								run();
	
								});

							$(".delivery2_btn").click(function(){
								$(".ORDER_DELIVERY").val("배송 완료");
								run();
	
								});

							function run(){
									$(".deliveryForm").submit();
								}

							
				   		</script>
				   		</form>
				   </div>
				   
				  </c:if>
				  
				 </c:forEach>
				</div>
				
				<ul class="orderView">
				 <c:forEach items="${orderView}" var="orderView">     
				 <li>
				  <div class="thumb">
				   <img src="${orderView.GOODS_THUMBIMG}" />
				  </div>
				  <div class="gdsInfo">
				   <p>
				    <span>상품명</span>${orderView.GOODS_NAME}<br />
				    <span>개당 가격</span><fmt:formatNumber pattern="###,###,###" value="${orderView.GOODS_PRICE}" /> 원<br />
				    <span>구입 수량</span>${orderView.CARTSTATUS} 개<br />
				    <span>최종 가격</span><fmt:formatNumber pattern="###,###,###" value="${orderView.GOODS_PRICE * orderView.CARTSTATUS}" /> 원
				    <span>최종 할인 가격</span><fmt:formatNumber pattern="###,###,###" value="${orderView.GOODS_DCPRICE * orderView.CARTSTATUS}" /> 원                  
				   </p>
				  </div>
				 </li>     
				 </c:forEach>
				</ul>
			
		</div>
	</section>

	

</div>
</body>
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
</html>
