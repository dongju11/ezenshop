<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>

<html>
<head>
	 <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link type="text/css" rel="stylesheet" href="<c:url value='/resources/magiczoomplus/magiczoomplus.css'/>"/>
	<script src="<c:url value='/resources/magiczoomplus/magiczoomplus.js'/>" charset="utf-8"></script>
	<script src='//unpkg.com/jquery@3/dist/jquery.min.js'></script>
	<script src='//unpkg.com/popper.js@1/dist/umd/popper.min.js'></script>
	<script src='//unpkg.com/bootstrap@4/dist/js/bootstrap.min.js'></script>
	<title>view</title>
	
	
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
		
		 div.GOODS div.GOODS_IMAGE { float:left; width:350px; }
		 div.GOODS div.GOODS_IMAGE img { width:350px; height:auto; }
		 
		 div.GOODS div.GOODSINFO { float:right; width:330px; font-size:22px; }
		 div.GOODS div.GOODSINFO p { margin:0 0 20px 0; }
		 div.GOODS div.GOODSINFO p span { display:inline-block; width:100px; margin-right:15px; }
		 
		 div.GOODS div.GOODSINFO p.cartSTATUS input { font-size:22px; width:50px; padding:5px; margin:0; border:1px solid #eee; }
		 div.GOODS div.GOODSINFO p.cartSTATUS button { font-size:26px; border:none; background:none; }
		 div.GOODS div.GOODSINFO p.addToCart { text-align:right; }
		 div.GOODS div.GOODS_DETAIL { font-size:18px; clear:both; padding-top:30px; }
		 div.goods div.goodsInfo p.cartStock button { font-size:26px; border:none; background:none; }
		 
	</style>
	
	<style type="text/css">
  
	@import url(https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css);

	.fa-beat {
	  animation:fa-beat 5s ease infinite;
	}
	@keyframes fa-beat {
	  0% {
	    transform:scale(1);
	  }
	  5% {
	    transform:scale(1.25);
	  }
	  20% {
	    transform:scale(1);
	  }
	  30% {
	    transform:scale(1);
	  }
	  35% {
	    transform:scale(1.25);
	  }
	  50% {
	    transform:scale(1);
	  }
	  55% {
	    transform:scale(1.25);
	  }
	  70% {
	    transform:scale(1);
	  }
	}

.starR{
     background: url('http://miuu227.godohosting.com/images/icon/ico_review.png') no-repeat right 0;
     background-size: auto 100%;
     width: 30px;
     height: 30px;
     display: inline-block;
     text-indent: -9999px;
     cursor: pointer;
   }
.starR.ons{background-position:0 0;}

	.starRc{
	  background: url('http://miuu227.godohosting.com/images/icon/ico_review.png') no-repeat right 0;
	  background-size: auto 100%;
	  width: 10px;
	  height: 10px;
	  display: inline-block;
	  text-indent: -9999px;
	  cursor: pointer;
	}
	.starRc.oncs{background-position:0 0;}
</style>
<script type="text/javascript">
$(document).ready(function() {
   $('.starRev span').click(function(){
        $(this).parent().children('span').removeClass('ons');
        $(this).addClass('ons').prevAll('span').addClass('ons');
        $("#REP_START").val($(this).text());
        return false;
      });

});

   </script>

</head>
<body>
<jsp:include page="../common/header.jsp"></jsp:include>
<div id="root">
		
	<section id="container">
		<div id="container_box">
		
			<section id="content">
				<form role="form" method="post">
					<input type="hidden" id="GOODS_NO" name="GOODS_NO" value="${view.GOODS_NO}" />
				</form>
				
				<div class="GOODS">
					<div class="GOODS_IMAGE">
						<img src="${pageContext.request.contextPath}/${view.GOODS_IMAGE}">
					</div>
					
					<div class="GOODS_INFO">
						<p class="GOODS_NAME"><span>상품명: </span>${view.GOODS_NAME}</p>
						
						<p class="CATENAME"><span>카테고리: </span>${view.CATENAME}</p>
						
						<p class="GOODS_BRAND"><span>브랜드: </span>${view.GOODS_BRAND}</p>
						
						<p class="GOODS_PRICE">
							<span>가격: </span><fmt:formatNumber pattern="###,###,###" value="${view.GOODS_PRICE}" /> 원
						</p>
						
						<p class="GOODS_DCPRICE">
							<span>할인가격: </span><fmt:formatNumber pattern="###,###,###" value="${view.GOODS_DCPRICE}" /> 원
						</p>
						
						<p class="GOODS_STATUS">
							<span>재고: </span><fmt:formatNumber pattern="###,###,###" value="${view.GOODS_STATUS}" /> 개
						</p>
						
						<p class="cartSTATUS">
							<span>구입 수량</span>
							<button type="button" class="plus">+</button>
							<input type="number" class="numBox" min="1" max="${view.GOODS_STATUS}" value="1" readonly="readonly"/>
							<button type="button" class="minus">-</button>
							
							<script>
								$(".plus").click(function(){
									var num = $(".numBox").val();
									var plusNum = Number(num) + 1;

									if(plusNum >= ${view.GOODS_STATUS}){
										$(".numBox").val(num);			
									} else {
										$(".numBox").val(plusNum);		
									}
								});

								$(".minus").click(function(){
									var num = $(".numBox").val();
									var minusNum = Number(num) - 1;

									if(minusNum <= 0) {
										$(".numBox").val(num);
									} else {
										$(".numBox").val(minusNum)
									}
								});
									
							</script>
						</p>
						
						<p><span>상품번호: </span>${view.GOODS_NO}</p>
						
						<p class="addToCart">
							<button type="button" class="addCart_btn">장바구니 담기</button>
		                  	<button class="btn btn-danger addJjim" type="button">
		                     <i class="fa fa-heart fa-beat"></i>
		                  	</button>
                			
							<script>
													
							$(".addCart_btn").click(function(){
								   var GOODS_NO = $("#GOODS_NO").val();
								   var CARTSTATUS = $(".numBox").val();
								      
								   var data = {
										   GOODS_NO : GOODS_NO,
								     CARTSTATUS : CARTSTATUS
								     };
								   
								   $.ajax({
								    url : "/controller/shop/view/addCart",
								    type : "post",
								    data : data,
								    success : function(result){

									  if(result == 1){
										  alert("카트 담기 성공");
										     $(".numBox").val("1");

										     var test = confirm('장바구니로 이동하시겠습니까?');
										     if(test) {
											     
												location.href = '/controller/shop/cartList';
											     }
										    
										  } else {
											  alert("회원만 사용가능");
											  $(".numBox").val("1");		
										  }
								    
								    },
								    error : function(){
								     alert("카트 담기 실패");
								    }
								   });
								  });

							$(".addJjim").click(function(){
								var num="${member.MEMBER_ID}";
								  if(num==""){
									  alert("로그인이 필요한 서비스입니다.");
									  return;
									}
									
								var GOODS_NO = $("#GOODS_NO").val();
								var CARTSTATUS = $(".numBox").val();

								var data = {
										   GOODS_NO : GOODS_NO,
										   CARTSTATUS : CARTSTATUS
								     };
									
									 $.ajax({
									 type : "post",
									 url : "/controller/shop/view/addJjim",
									 data : data,
									success : function(data){
									 if(data == true){
									alert("찜목록에 추가했습니다.");
									 $(".numBox").val("1");
									}else{
									alert("이미 찜목록에 있습니다.");
									 }
								 },
								 error : function(){
								     alert("찜하기 실패");
								 }    
							});  
						});
							</script>
										
							
						
					</div>
					<div class="GOODS_DETAIL">상세설명 : ${view.GOODS_DETAIL}</div>
				</div>
				
				<div id="reply">
					<c:if test="${member == null}">
						<p>상품평을 남기시려면<a href="../member/login">로그인</a>을 해주세요</p>
					</c:if>
					
					<c:if test="${member != null}">
					<section class="replyForm">
						<form role="form" method="post" autocomplete="off">
						
							<input type="hidden" name="GOODS_NO" value="${view.GOODS_NO}">
						
							<div class="starRev">
								<span class="starR ons">1</span>
			                    <span class="starR">2</span>
			                    <span class="starR">3</span>
			                    <span class="starR">4</span>
			                    <span class="starR">5</span> 
			                    <input type="hidden" id="REP_START" name="REP_START" value="1"> 
							</div>
							
							<div class="input_area">
								<textarea name="REP_CON" id="REP_CON"></textarea>
							</div>
							
							<div class="input_area">
								<button type="submit" id="reply_btn">상품평 남기기</button>
							
							
							</div>
						</form>
					</section>
					</c:if>
					
					<section class="replyList">
						<ol>
							<c:forEach items="${reply}" var="reply">
								<li>
									<div class="userInfo" id="reviewList">
										<c:forEach var="i" begin="1" end="5">
											<c:choose>
											<c:when test= "${i>reply.REP_START}"><span class="starRc">별</span></c:when>
											 <c:otherwise> <span class="starRc oncs">별</span></c:otherwise>
											</c:choose>
										</c:forEach>	
										<span class="userName">${reply.MEMBER_NAME}</span>
										<span class="date"><fmt:formatDate value="${reply.REP_DATE}" pattern="yyyy-MM-dd" /></span>									
									</div>
									<div class="replyContent">${reply.REP_CON}</div>
								</li>
								</c:forEach>
						</ol>
					
						 
					</section>
				</div>
				
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
