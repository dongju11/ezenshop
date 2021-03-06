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
	
	.allCheck { float:left; width:200px; }
.allCheck input { width:16px; height:16px; }
.allCheck label { margin-left:10px; }
.delBtn { float:right; width:300px; text-align:right; }

.checkBox { float:left; width:30px; }
.checkBox input { width:16px; height:16px; }

	
	section#content ul li { margin:10px 0; }
 section#content ul li img { width:250px; height:250px; }
 section#content ul li::after { content:""; display:block; clear:both; }
 section#content div.GOODS_THUMBIMG { float:left; width:250px; }
 section#content div.GOODSINFO { float:right; width:calc(100% - 270px); }
 section#content div.GOODSINFO { font-size:20px; line-height:2; }
 section#content div.GOODSINFO span { display:inline-block; width:100px; font-weight:bold; margin-right:10px; }
 section#content div.GOODSINFO .delete { text-align:right; }
 
		
		
		.listResult { padding:20px; background:#eee; }
.listResult .sum { float:left; width:45%; font-size:22px; }

.listResult .orderOpne { float:right; width:45%; text-align:right; }

.listResult::after { content:""; display:block; clear:both; }
		
		.orderInfo { border:5px solid #eee; padding:20px; display:none; }
		.orderInfo .inputArea { margin:10px 0; }
		.orderInfo .inputArea label { display:inline-block; width:120px; margin-right:10px; }
		.orderInfo .inputArea input { font-size:14px; padding:5px; }


.orderInfo .inputArea:last-child { margin-top:30px; }

		
	</style>
	
</head>
<body>
<jsp:include page="../common/header.jsp"></jsp:include>
<div id="root">
	

	<h3>????????????</h3>
	<section id="container">
		<div id="container_box">
			<section id="content">
				<ul>
					<li>
						<div class="allCheck">
							<input type="checkbox" name="allCheck" id="allCheck" /><label for="allCheck">?????? ??????</label>
							
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
							<button type="button" class="selectDelete_btn btn-danger">?????? ??????</button>
							
							<script>
							$(".selectDelete_btn").click(function(){
								var confirm_val = confirm("?????? ?????????????????????????");

								if(confirm_val) {
									var checkArr = new Array();

									$("input[class='chBox']:checked").each(function(){
										checkArr.push($(this).attr("data-CART_NO"));
									});

									$.ajax({
										url : "/controller/shop/deleteCart",
										type : "post",
										data : { chbox : checkArr },
										success : function(result){

											if(result ==1){
												location.href = "/controller/shop/cartList";
											} else {
												alert("?????? ??????");		
											}
										}
									});
								}
							});
							</script>
							
						</div>
					</li>
					
					<c:set var="sum" value="0" />
				
					<c:forEach items="${cartList}" var="cartList">
					<li>
						<div class="checkBox">
							<input type="checkbox" name="chBox" class="chBox" data-CART_NO="${cartList.CART_NO}" />
							
							<script>
								$(".chBox").click(function(){
									$("#allCheck").prop("checked", false);
								});
							</script>
						
						</div>
						<div class="GOODS_THUMBIMG">
							<img src="${pageContext.request.contextPath}/${cartList.GOODS_THUMBIMG}" />
						</div>
						<div class="GOODSINFO">
							<p>
								<span>????????? :</span>${cartList.GOODS_NAME}<br />
								<span>?????? ?????? :</span>
									<fmt:formatNumber pattern="###,###,###" value="${cartList.GOODS_PRICE}" />???<br />
								<span>?????? ?????? :</span>
									<fmt:formatNumber pattern="###,###,###" value="${cartList.GOODS_DCPRICE}" />???<br />
								<span>?????? ?????? :</span>${cartList.CARTSTATUS} ???<br />
								<c:if test="${{cartList.GOODS_PRICE} == {cartList.GOODS_DCPRICE}}">
								<span>?????? ?????? :</span>
								<fmt:formatNumber pattern="###,###,###" value="${cartList.GOODS_PRICE * cartList.CARTSTATUS}" /> ???
								</c:if>
								<span>?????? ?????? :</span>
								<fmt:formatNumber pattern="###,###,###" value="${cartList.GOODS_DCPRICE * cartList.CARTSTATUS}" /> ???
								<span>????????? :</span>${cartList.GOODS_BRAND}<br />
								<span>????????? :</span>${cartList.GOODS_SHIPPING}???<br />
								<span>????????? ?????? ?????? ?????? :</span>
								<fmt:formatNumber pattern="###,###,###" value="${cartList.GOODS_DCPRICE * cartList.CARTSTATUS + cartList.GOODS_SHIPPING}" /> ???
							
							</p>
							
							<div class="delete">
								<button type="button" class="delete_${cartList.CART_NO}_btn btn-danger" data-CART_NO="${cartList.CART_NO}">??????</button>
								
								<script>
									$(".delete_${cartList.CART_NO}_btn").click(function(){
										var confirm_val = confirm("?????? ?????????????????????????");

										if(confirm_val) {
											var checkArr = new Array();

											checkArr.push($(this).attr("data-CART_NO"));

											$.ajax({
												url : "/controller/shop/deleteCart",
												type : "post",
												data : { chbox : checkArr },
												success : function(result) {

													if(result == 1) {
														location.href = "/controller/shop/cartList";
														
														} else {
															alert("?????? ??????");
														}

													}


												});
												
											}
										});
								</script>
							</div>
						
						</div>
					</li>
					
					
					<c:set var="sum" value="${sum + (cartList.GOODS_DCPRICE * cartList.CARTSTATUS) + cartList.GOODS_SHIPPING}" />
					
					
					
					</c:forEach>
				
				
				</ul>
				<div class="listResult">
				 <div class="sum">
				  ??? ?????? : <fmt:formatNumber pattern="###,###,###" value="${sum}" />???
				 </div>
				 <div class="orderOpne">
				  <button type="button" class="orderOpne_bnt btn-danger">?????? ?????? ??????</button>
				  <script>
					$(".orderOpne_bnt").click(function(){
						$(".orderInfo").slideDown();
						$(".orderOpne_bnt").slideUp();
					});
				  </script>
				  
				 </div>
				</div>
				
				<div class="orderInfo">
					<form role="form" method="post" autocomplete="off">
						<input type="hidden" name="ORDER_AMOUNT" value="${sum}" />
					
					
					<div class="inputArea">
						<label for="">?????????</label>
						<input type="text" name="ORDER_REC" id="ORDER_REC" class="form-control" required="required" value="${member.MEMBER_NAME}" />				
					</div>
					
					<div class="inputArea">
						<label for="ORDER_PHON">????????? ?????????</label>
						<input type="text" name="ORDER_PHON" id="ORDER_PHON" class="form-control" required="required" value="${member.MEMBER_PHONE}"/>					
					</div>
					
					<div class="inputArea">
						<label for="MEMBER_ADDR">?????? ??????</label>
						<input type="text" name="MEMBER_ADDR" id="MEMBER_ADDR" class="form-control" required="required" value="${member.MEMBER_ADDR}" />					
						
					</div>
					
					<div class="inputArea">
						<button type="submit" class="order_btn btn btn-primary btn-danger">??????</button>
						<button type="button" class="cancel_btn btn btn-danger">??????</button>
						
					    <script>
							$(".cancel_btn").click(function(){
								$(".orderInfo").slideUp();
								$(".orderOpne_bnt").slideDown();
							});
				 		 </script>
					</div>
					</form>
				</div>
				
				
			</section>
			
			
		</div>
	</section>

	

</div>
</body>
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

</html>
