<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>

<html>
<head>
	<meta charset="UTF-8">
    
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
		
	</style>
	
</head>
<body>
<jsp:include page="../common/header.jsp"></jsp:include>
<div id="root">
	
			
	
	<section id="container">
		<div id="container_box">
		
			<section id="content">
			<h1 style=text-align:center>BEST ITEM</h1> <br/><br/>
				<ul>
					 <c:forEach items="${bestGoods}" var="bestGoods">
					 <li>
			 			 <div class="GOODS_THUMB">
			  				 <img src="${pageContext.request.contextPath}/${bestGoods.GOODS_THUMBIMG}">
			  			</div> 
			 			<div class="GOODS_NAME">
			  				 <a href="${pageContext.request.contextPath}/shop/view?n=${bestGoods.GOODS_NO}">${bestGoods.GOODS_NAME}</a>
			 			</div>
			 			<div class="GOODS_PRICE">
			  				 <a href="${pageContext.request.contextPath}/shop/view?n=${bestGoods.GOODS_NO}">${bestGoods.GOODS_PRICE}</a>
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
