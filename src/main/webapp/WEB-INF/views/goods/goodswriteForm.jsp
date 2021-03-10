<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<html>
<head>
	 	
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

		<link href="https://cdn.jsdelivr.net/npm/summernote@0.8.18/dist/summernote.min.css" rel="stylesheet">
		<script src="https://cdn.jsdelivr.net/npm/summernote@0.8.18/dist/summernote.min.js"></script>	 	
		<script src="http://cdnjs.cloudflare.com/ajax/libs/summernote/0.8.9/summernote.js" defer></script> 		 	

		<style>
			.select_img img{margin:20px 0;}
		</style>
</head>
<script>
$(document).ready(function() {
	
	$('#GOODS_DETAIL').summernote({
    placeholder: '내용을 입력해주세요',
    tabsize: 1,
    height: 100,
    focus: true,
    lang: "ko-KR",
     
  })
});
</script>
<body>
<jsp:include page="../common/header.jsp"></jsp:include>
	
 	<div class="container">	
 	<h1 class="text-center">상품 등록</h1>
		<div class="col-lg-0">
			<div class="jumbotron" style="padding-top: 20px;">
 			
		<form role="form" method="post" autocomplete="off" enctype="multipart/form-data">
	 		
	 		<div class="form-row">
	 		 	<label>1차 분류</label>
		 			<select class="category1">
		 				<option value="">전체</option>
		 			</select>
		 
		   		 <label>2차 분류</label>
		 			<select class="category2" name="GOODS_CATEGORY">
		 				<option value="">전체</option>
					</select>
		 	</div>
		 	
			<div class="form-row">
		 		<div class="form-group col-md-2">
 					<label for="GOODS_NAME">상품명</label>
 					<input type="text" class="form-control" id="GOODS_NAME" name="GOODS_NAME" />
		 		</div>
		 
		    	<div class="form-group col-md-2">
 					<label for="GOODS_PRICE">상품가격</label>
 					<input type="text" class="form-control" id="GOODS_PRICE" name="GOODS_PRICE" />
		   		</div> 
		 
		  		<div class="form-group col-md-2">
 					<label for="GOODS_DCPRICE">상품할인가격</label>
 					<input type="text" class="form-control" id="GOODS_DCPRICE" name="GOODS_DCPRICE" />
		 		</div> 
		 	</div>
		 
		   <div class="form-row">
		  		<div class="form-group col-md-2">
 					<label for="GOODS_SIMPLE">간략설명</label>
 					<input type="text" class="form-control" id="GOODS_SIMPLE" name="GOODS_SIMPLE" />
		 		</div>  
		 
				 <div class="form-group col-md-2">
 					<label for="GOODS_BRAND">브랜드</label>
 					<input type="text" class="form-control" id="GOODS_BRAND" name="GOODS_BRAND" />
				 </div>  
		 
				 <div class="form-group col-md-2">
 					<label for="GOODS_SHIPPING">배송비</label>
 					<input type="text" class="form-control" id="GOODS_SHIPPING" name="GOODS_SHIPPING" />
		 		</div>  
				 <div class="form-group col-md-2">
 					<label for="GOODS_STATUS">수량</label>
 					<input type="text" class="form-control" id="GOODS_STATUS" name="GOODS_STATUS" />
		 		</div>
			 </div>
		
		  <div id="summernote" class="inputArea">
 			<label for="GOODS_DETAIL">상세설명</label> <br/><br/> <br/>
 			<textarea rows="5" cols="50" id="GOODS_DETAIL" name="GOODS_DETAIL"></textarea>
		
			<!-- <script>
				var ckeditor_config = {
						resize_enaleb : false,
						enterMode : CKEDITOR.ENTER_BR,
						shiftEnterMode : CKEDITOR.ENTER_P,
						filebrowserUploadUrl : "${pageContext.request.contextPath}/goods/ckUpload"
				};

				CKEDITOR.replace("GOODS_DETAIL", ckeditor_config);
			</script> -->
		
		 </div>    
		 
		 <div class="inputArea">
 			<label for="GOODS_IMAGE">이미지</label>
 			<input type="file" id="GOODS_IMAGE" name="file" />
 			<div class="select_img"><img src="" /></div>
 
			 <script>
			 	 $("#GOODS_IMAGE").change(function(){
			 		 if(this.files && this.files[0]) {
			  			  var reader = new FileReader;
			   			  reader.onload = function(data) {
			    			 $(".select_img img").attr("src", data.target.result).width(500);        
			   				 }
			   			  reader.readAsDataURL(this.files[0]);
			  		 }
			  });
			 </script>
			 
			 <%=request.getRealPath("/") %>
			 
			</div>

		<div class="inputArea">
		 <button type="submit" id="goodswrite_Btn" class="btn btn-primary">등록</button>
		 <button type="submit" id="goodswrite_Btn" class="btn btn-primary">취소</button>
		</div>
	 
	</form>
	
	
  </div>  
   </div>
   </div>
                   

 <script>
		var jsonData = JSON.parse('${category}');

		var cate1Arr = new Array();
		var cate1Obj = new Object();

		
		for(var i = 0; i < jsonData.length; i++) {
			
			if(jsonData[i].level == "1") {  
				cate1Obj = new Object();  
				
				
				cate1Obj.CATECODE = jsonData[i].CATECODE; 
				cate1Obj.CATENAME = jsonData[i].CATENAME;
				
				
				cate1Arr.push(cate1Obj);
			}
		}

	
		var cate1Select = $("select.category1")

		for(var i = 0; i < cate1Arr.length; i++) {

			
			cate1Select.append("<option value='" + cate1Arr[i].CATECODE + "'>"
								+ cate1Arr[i].CATENAME + "</option>");	
		}

		$(document).on("change", "select.category1", function(){

			 var cate2Arr = new Array();
			 var cate2Obj = new Object();
			 
			
			 for(var i = 0; i < jsonData.length; i++) {
			  
			  if(jsonData[i].level == "2") {
			   cate2Obj = new Object();  
			   cate2Obj.CATECODE = jsonData[i].CATECODE;
			   cate2Obj.CATENAME = jsonData[i].CATENAME;
			   cate2Obj.CATECODEREF = jsonData[i].CATECODEREF;
			   
			   cate2Arr.push(cate2Obj);
			  }
			 }
			 
			 var cate2Select = $("select.category2");
			 						 
			 cate2Select.children().remove();

			 $("option:selected", this).each(function(){
			  
			  var selectVal = $(this).val(); 
			   
			  cate2Select.append("<option value='" + selectVal + "'>전체</option>");
			  
			  for(var i = 0; i < cate2Arr.length; i++) {
			   if(selectVal == cate2Arr[i].CATECODEREF) {
			    cate2Select.append("<option value='" + cate2Arr[i].CATECODE + "'>"
			         + cate2Arr[i].CATENAME + "</option>");
			   }
			  }
			  
			 });
			 
			});
		
		var regExp = /[^0-9]/gi;

		$("#GOODS_PRICE").keyup(function(){ numCheck($(this)); });
		$("#GOODS_STATUS").keyup(function(){ numCheck($(this)); });

		function numCheck(selector) {
		 var tempVal = selector.val();
		 selector.val(tempVal.replace(regExp, ""));
		}
             </script>
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