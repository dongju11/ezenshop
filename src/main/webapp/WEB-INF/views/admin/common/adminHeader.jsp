<%@ page language="java" contentType="text/html; charset=UTF-8" 
    pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %> 
<!doctype html>

  <html>
  <head> 
  
	<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<title>Home</title>
	
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="description" content="Free HTML5 Website Template by FreeHTML5.co" />
	<meta name="keywords" content="free html5, free template, free bootstrap, free website template, html5, css3, mobile first, responsive" />
	<meta name="author" content="FreeHTML5.co" />


  	<!-- Facebook and Twitter integration -->
	<meta property="og:title" content=""/>
	<meta property="og:image" content=""/>
	<meta property="og:url" content=""/>
	<meta property="og:site_name" content=""/>
	<meta property="og:description" content=""/>
	<meta name="twitter:title" content="" />
	<meta name="twitter:image" content="" />
	<meta name="twitter:url" content="" />
	<meta name="twitter:card" content="" />

	<!-- Place favicon.ico and apple-touch-icon.png in the root directory -->
	<link rel="shortcut icon" href="favicon.ico">

	<link href='https://fonts.googleapis.com/css?family=Roboto:400,300,600,400italic,700' rel='stylesheet' type='text/css'>
	<link href='https://fonts.googleapis.com/css?family=Montserrat:400,700' rel='stylesheet' type='text/css'>
	
	<!-- Animate.css -->
	<link rel="stylesheet" href="/controller/resources/css/animate.css">
	<!-- Icomoon Icon Fonts-->
	<link rel="stylesheet" href="/controller/resources/css/icomoon.css">
	<!-- Bootstrap  -->
	<link rel="stylesheet" href="/controller/resources/css/bootstrap.css">
	<!-- Owl Carousel -->
	<link rel="stylesheet" href="/controller/resources/css/owl.carousel.min.css">
	<link rel="stylesheet" href="/controller/resources/css/owl.theme.default.min.css">
	<!-- Theme style  -->
	<link rel="stylesheet" href="/controller/resources/css/style.css">
	<!-- Modernizr JS -->
	<script src="/controller/resources/js/modernizr-2.6.2.min.js"></script>	
    </head>
  <body>
  <ul class="nav navbar-nav navbar-right">
        	<li class="dropdown"> 
        	
        		<a href="#" class="dropdown-toggle, btn btn-danger"
        			data-toggle="dropdown" role="button" aria-haspopup="true"
        			aria-expanded="false"> ฅ^•ﻌ•^ฅ <span class="caret"></span></a>
        			
        		<ul class="dropdown-menu">
        			<c:if test="${member == null}">
        			<li class="active"><a href="${pageContext.request.contextPath}/member/login">로그인</a></li>
        			</c:if>
        			<c:if test="${member != null}">
        			
        				<c:if test="${member.MEMBER_VERIFY == 1}">
        					<li>
        						<a href="${pageContext.request.contextPath}/admin/adminhome">관리자 화면</a>
        					</li>
        				</c:if>
        				
        			<li class="active"><a href="${pageContext.request.contextPath}/member/logout">로그아웃</a></li>
        			<li><a href="${pageContext.request.contextPath}/member/mypage">마이페이지</a></li>
        			</c:if>
        			<li><a href="${pageContext.request.contextPath}/member/memberinsert">회원가입</a></li>
        			<li><a href="#">장바구니</a></li>
        			<li><a href="#">찜한상품</a></li>
        		</ul>	
        	</li>
         </ul>
  
  
  
  
  
   <div id="fh5co-page">
   		<a class="navbar-brand" href="${pageContext.request.contextPath}/admin/adminhome"></a>
		<a href="${pageContext.request.contextPath}" class="js-fh5co-nav-toggle fh5co-nav-toggle"><i></i></a>
		<aside id="fh5co-aside" role="complementary" class="border js-fullheight">
			<h1 id="fh5co-logo"><a href="${pageContext.request.contextPath}"><img src="/controller/resources/images/logo2.png" width="112" height="112" alt="Free HTML5 Bootstrap Website Template" /></a></h1>
			<nav id="fh5co-main-menu" role="navigation">
			 
				<ul>
					<br>
				
      				<div class="dropdown">
    				<button class="btn btn-primary btn-lg btn-block dropdown-toggle" type="button" data-toggle="dropdown">상품
   					 <span class="caret"></span></button>
    				<ul class="dropdown-menu">
      				<ul class="low">
				<li><a class="dropdown-item" href="${pageContext.request.contextPath}/goods/goodswriteForm">(공용)상품 등록</a></li>
	              <li><a class="dropdown-item" href="${pageContext.request.contextPath}/goods/goodslist">(관리자)상품 목록</a></li>
	              <li><a class="dropdown-item" href="${pageContext.request.contextPath}/shop/shopmain">(사용자)상품 목록</a></li>
	              <li><a class="dropdown-item" href="${pageContext.request.contextPath}/shop/cartList">(사용자)장바구니</a></li>
	              <li><a class="dropdown-item" href="${pageContext.request.contextPath}/shop/orderList">(사용자)주문 목록</a></li>
		</ul>
      				</ul></div>
      		<br>
      		
      		
      				<div class="dropdown">
    				<button class="btn btn-primary btn-lg btn-block dropdown-toggle" type="button" data-toggle="dropdown">관리자용 게시판
   					 <span class="caret"></span></button>
    				<ul class="dropdown-menu">
      					<ul class="low"> 
			 	  <li><a href="${pageContext.request.contextPath}/admin/notice/noticeList">공지사항</a></li>
	              <li><a href="${pageContext.request.contextPath}/admin/board/QnaList">문의 게시판</a><li>
	              <li><a href="${pageContext.request.contextPath}/admin/board/boardList">자유 게시판</a><li>
	              <li><a href="${pageContext.request.contextPath}/admin/board/reportBoardList">신고 게시판</a></li>
	              <li><a href="${pageContext.request.contextPath}/admin/as/aslist">교환/환불/반품 게시판</a></li>
		</ul></ul></div>
		
        		<br>
        		
        		<div class="dropdown">
    				<button class="btn btn-primary btn-lg btn-block dropdown-toggle" type="button" data-toggle="dropdown">관리자용 상품
   					 <span class="caret"></span></button>
    				<ul class="dropdown-menu">
      					<ul class="low"> 
        		<li><a href="#">회원목록</a></li>
        		<li><a href="${pageContext.request.contextPath}/admin/goods/goodslistSearch">상품목록(페이징검색)</a></li>
        		<li><a href="${pageContext.request.contextPath}/admin/shop/orderList">주문목록</a><li>
        		<li><a href="${pageContext.request.contextPath}/admin/shop/allReply">소감목록</a></li>
        		</ul></ul></div>
        		
        		
        			
	            </ul>
	            </nav>
	           </aside>
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
  </body>
</html>



