<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<html>
<head>
<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<title>Home</title>
	
	<meta name="viewport" content="width=device-width, initial-scale=1">
	
	<!-- 구글 한글 적용폰트 -->
	<link rel="preconnect" href="https://fonts.gstatic.com">
	<link href="https://fonts.googleapis.com/css2?family=Jua&family=Poor+Story&display=swap" rel="stylesheet">
	
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
	<script src='https://code.jquery.com/jquery-3.3.1.min.js'></script>	 
	
	<style>
	
	 	table.type03 {
  border-collapse: collapse;
  text-align: left;
  line-height: 1.5;
  border-top: 1px solid #ccc;
  border-left: 3px solid #369;
  margin : 20px 10px;
}
table.type03 th {
  width: 147px;
  padding: 10px;
  font-weight: bold;
  vertical-align: top;
  color: #153d73;
  border-right: 1px solid #ccc;
  border-bottom: 1px solid #ccc;

}
table.type03 td {
  width: 349px;
  padding: 10px;
  vertical-align: top;
  border-right: 1px solid #ccc;
  border-bottom: 1px solid #ccc;
}
	 	</style>
</head>
<body>
<jsp:include page="../common/header.jsp"></jsp:include>

<div class="container">		
		<div class="col-sm-10">	
			<div class="jumbotron" style="padding-top: 20px;">
				<form role="form" method="post" autocomplete="off">
		<h3 style="text-align: center;">회원정보 수정</h3>
	<p>
		<label for="MEMBER_ID">아이디</label> 
		<input type="text" id="MEMBER_ID" name="MEMBER_ID" class="form-control" value="${member.MEMBER_ID}"/>
	</p>
	<p>
		<label for="MEMBER_PW">수정 비밀번호</label>
		<input type="password" id="MEMBER_PW"  class="form-control" name="MEMBER_PW" />
	</p>
	<p>
		<label for="MEMBER_NAME">이름</label>
		<input type="text" id="MEMBER_NAME"  class="form-control" name="MEMBER_NAME" />
	</p>
	<p>
		<label for="MEMBER_PHONE">휴대폰 번호</label>
		<input type="text" id="MEMBER_PHONE" class="form-control" name="MEMBER_PHONE" />
	</p>
	<p>		
					<input type="text" name="MEMBER_ADDR" id="sample2_address" class="form-control" placeholder="주소"><br>
					<input type="button" onclick="sample2_execDaumPostcode()" class="btn btn-danger" value="우편번호 찾기"><br>
				</p>
					<!-- iOS에서는 position:fixed 버그가 있음, 적용하는 사이트에 맞게 position:absolute 등을 이용하여 top,left값 조정 필요 -->
					<div id="layer" style="display:none;position:fixed;overflow:hidden;z-index:1;-webkit-overflow-scrolling:touch;">
						<img src="//t1.daumcdn.net/postcode/resource/images/close.png" id="btnCloseLayer" style="cursor:pointer;position:absolute;right:-3px;top:-3px;z-index:1" onclick="closeDaumPostcode()" alt="닫기 버튼">
</div>

<script src="https://t1.daumcdn.net/mapjsapi/bundle/postcode/prod/postcode.v2.js"></script>
<script>
    // 우편번호 찾기 화면을 넣을 element
    var element_layer = document.getElementById('layer');

    function closeDaumPostcode() {
        // iframe을 넣은 element를 안보이게 한다.
        element_layer.style.display = 'none';
    }

    function sample2_execDaumPostcode() {
        new daum.Postcode({
            oncomplete: function(data) {
                // 검색결과 항목을 클릭했을때 실행할 코드를 작성하는 부분.

                // 각 주소의 노출 규칙에 따라 주소를 조합한다.
                // 내려오는 변수가 값이 없는 경우엔 공백('')값을 가지므로, 이를 참고하여 분기 한다.
                var addr = ''; // 주소 변수
                var extraAddr = ''; // 참고항목 변수

                //사용자가 선택한 주소 타입에 따라 해당 주소 값을 가져온다.
                if (data.userSelectedType === 'R') { // 사용자가 도로명 주소를 선택했을 경우
                    addr = data.roadAddress;
                } else { // 사용자가 지번 주소를 선택했을 경우(J)
                    addr = data.jibunAddress;
                }    
             
                document.getElementById("sample2_address").value = addr;
                // 커서를 상세주소 필드로 이동한다.
                document.getElementById("sample2_address").focus();

                // iframe을 넣은 element를 안보이게 한다.
                // (autoClose:false 기능을 이용한다면, 아래 코드를 제거해야 화면에서 사라지지 않는다.)
                element_layer.style.display = 'none';
            },
            width : '100%',
            height : '100%',
            maxSuggestItems : 5
        }).embed(element_layer);

        // iframe을 넣은 element를 보이게 한다.
        element_layer.style.display = 'block';

        // iframe을 넣은 element의 위치를 화면의 가운데로 이동시킨다.
        initLayerPosition();
    }

    // 브라우저의 크기 변경에 따라 레이어를 가운데로 이동시키고자 하실때에는
    // resize이벤트나, orientationchange이벤트를 이용하여 값이 변경될때마다 아래 함수를 실행 시켜 주시거나,
    // 직접 element_layer의 top,left값을 수정해 주시면 됩니다.
    function initLayerPosition(){
        var width = 300; //우편번호서비스가 들어갈 element의 width
        var height = 400; //우편번호서비스가 들어갈 element의 height
        var borderWidth = 5; //샘플에서 사용하는 border의 두께

       	 // 위에서 선언한 값들을 실제 element에 넣는다.
       	 element_layer.style.width = width + 'px';
       	 element_layer.style.height = height + 'px';
       	 element_layer.style.border = borderWidth + 'px solid';
       	 // 실행되는 순간의 화면 너비와 높이 값을 가져와서 중앙에 뜰 수 있도록 위치를 계산한다.
       	 element_layer.style.left = (((window.innerWidth || document.documentElement.clientWidth) - width)/2 - borderWidth) + 'px';
       	 element_layer.style.top = (((window.innerHeight || document.documentElement.clientHeight) - height)/2 - borderWidth) + 'px';
    	}
</script>
	<p>
		<label for="MEMBER_BIRTH">생일</label>
		<input type="text" id="MEMBER_BIRTH" class="form-control" name="MEMBER_BIRTH" />
	</p>
	<p>
		<label for="MEMBER_EMAIL">이메일</label>
		<input type="email" id="MEMBER_EAMIL"  class="form-control" name="MEMBER_EMAIL" />
	</p>
	
	
	<p>
		<button type="submit" class="btn btn-danger">회원정보 수정</button>
	</p>
	<p>
		<button type="button" class="btn btn-danger" onclick="location.href='mypage'">취소</button>
	</p>

	
</form>
</div>
</div>
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