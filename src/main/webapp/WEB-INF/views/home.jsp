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
    </head>
    
<body>
<jsp:include page="common/header.jsp"></jsp:include>

	<div id="fh5co-main">

			<div class="fh5co-narrow-content">
				<h2 class="fh5co-heading animate-box" data-animate-effect="fadeInCenter">EZENSHOP <span>애완동물 용품 판매점</span></h2>
				<div class="row animate-box" data-animate-effect="fadeInLCenter">
					<div class="col-md-10 col-sm-10 col-xs-10 col-xxs-20 work-item">
						<a href="${pageContext.request.contextPath}/member/memberinsert">
					<img src="resources/images/bg.png" width="3045" height="200" class="img-responsive">
							
						</a>
					</div>
					
					<div class="clearfix visible-md-block"></div>
					
				</div>
			</div>


			<div class="fh5co-testimonial" >
				<div class="fh5co-narrow-content">
					<div class="owl-carousel-fullwidth animate-box" data-animate-effect="fadeInLeft">
		            <div class="item">
		            	<figure>
		            		<img src="resources/images/testimonial_person2.jpg" alt="Free HTML5 Bootstrap Template">
		            	</figure>
		              	<p class="text-center quote">&ldquo;강아지는 코로 세상을 읽고 소변을 통해 역사를 쓴다. &rdquo; <cite class="author">&mdash; J.R Ackerley</cite></p>
		            </div>
		            <div class="item">
		            	<figure>
		            		<img src="resources/images/testimonial_person3.jpg" alt="Free HTML5 Bootstrap Template">
		            	</figure>
		              	<p class="text-center quote">&ldquo;당신의 얼굴을 핥아주는 강아지만한 정신과의사는 없다. &rdquo;<cite class="author">&mdash; Chas Doran</cite></p>
		            </div>
		            <div class="item">
		            	<figure>
		            		<img src="resources/images/testimonial_person4.jpg" alt="Free HTML5 Bootstrap Template">
		            	</figure>
		              	<p class="text-center quote">&ldquo;사람의 영혼은 개를 대하는 모습으로 알 수 있다. &rdquo;<cite class="author">&mdash; Ben Williams</cite></p>
		            </div>
		          </div>
				</div>
			</div>


			<div class="fh5co-narrow-content">
				<h2 class="fh5co-heading animate-box" data-animate-effect="fadeInLeft">우리의 친구들은 <span>무엇을 사랑할까요?</span></h2>
				<div class="row">
					<div class="col-md-6">
						<div class="fh5co-feature animate-box" data-animate-effect="fadeInLeft">
							<div class="fh5co-icon">
								<i class="icon-strategy"></i>
							</div>
							<div class="fh5co-text">
								<h3>주인의 사랑</h3>
								<p>우리 친구들은 주인에게 무심한듯 언제는 너무 반가워하지만 그 마음속에는 '사랑' 을 원하고 있습니다. </p>
							</div>
						</div>
					</div>
					<div class="col-md-6">
						<div class="fh5co-feature animate-box" data-animate-effect="fadeInLeft">
							<div class="fh5co-icon">
								<i class="icon-telescope"></i>
							</div>
							<div class="fh5co-text">
								<h3>관찰</h3>
								<p>우리 친구들은 주인과 소통하기 위해 많은 것들을 하는데 그런 비언어적인 행동을 잘 관찰하여 원하는 것들을 채워줌으로 서로의 관계가 더욱 친밀해집니다. </p>
							</div>
						</div>
					</div>

					<div class="col-md-6">
						<div class="fh5co-feature animate-box" data-animate-effect="fadeInLeft">
							<div class="fh5co-icon">
								<i class="icon-circle-compass"></i>
							</div>
							<div class="fh5co-text">
								<h3>같은 목표</h3>
								<p>우리 친구들은 항상 주인과 같은 목표와 생각을 가지고 싶어합니다. 그런 친구들이 장난을 치거나 가까이 와서 뛴다면 같이 놀아주세요 </p>
							</div>
						</div>
					</div>
					<div class="col-md-6">
						<div class="fh5co-feature animate-box" data-animate-effect="fadeInLeft">
							<div class="fh5co-icon">
								<i class="icon-tools-2"></i>
							</div>
							<div class="fh5co-text">
								<h3>함께함</h3>
								<p>친구들은 항상 주인과 함께 하기를 원합니다. 만들거나 뛰거나 밥을 먹거나 다양하게요! 함께 한다면 행복한 시간들이 될 것입니다. </p>
							</div>
						</div>
					</div>

				</div>
			</div>

			<div class="fh5co-counters" style="background-image: url(/controller/resources/images/hero.jpg);" data-stellar-background-ratio="0.5" id="counter-animate">
				<div class="fh5co-narrow-content animate-box">
					<div class="row" >
						<div class="col-md-4 text-center">
							<span class="fh5co-counter js-counter" data-from="0" data-to="67" data-speed="5000" data-refresh-interval="50"></span>
							<span class="fh5co-counter-label">이달의 구조된 애완동물</span>
						</div>
						<div class="col-md-4 text-center">
							<span class="fh5co-counter js-counter" data-from="0" data-to="130" data-speed="5000" data-refresh-interval="50"></span>
							<span class="fh5co-counter-label">이달의 입양된 애완동물</span>
						</div>
						<div class="col-md-4 text-center">
							<span class="fh5co-counter js-counter" data-from="0" data-to="27232" data-speed="5000" data-refresh-interval="50"></span>
							<span class="fh5co-counter-label">우리의 많은 가족들이 있어요</span>
						</div>
					</div>
				</div>
			</div>
		
			<div class="fh5co-cards">
				<div class="fh5co-narrow-content">
					<h2 class="fh5co-heading animate-box" data-animate-effect="fadeInLeft">다른 정보가 필요하신가요?</h2>

					<div class="fh5co-flex-wrap">
						<div class="fh5co-card animate-box" data-animate-effect="fadeInLeft">
							<h5>사랑의가족</h5>
							<p>우리와 함께 하는 가족들을 소개합니다. 이 곳에서는 우리 친구들이 무료 분양과 적극적인 구조활동을 하고 있습니다. 더 궁금하신 부분이 있다면 밑에 '들어가기'를 클릭하세요.</p>
							<p><a href="https://www.zooseyo.com/search/search.php" class="btn btn-md btn-primary">들어가기</a></p>
						</div>
						<div class="fh5co-card animate-box" data-animate-effect="fadeInLeft">
							<h5>가족들을 모십니다</h5>
							<p>이 곳도 저희와 비슷한 생각을 가지고 활동하시는 단체입니다. 특히 고양이의 대한 정보와 지식들을 기반으로 활동 하시는 분들인데요. 더 궁금하신 부분이 있다면 밑에 '들어가기'를 클릭하세요.</p>
							<p><a href="https://myohagae.com/bbs_list.php?tb=board_music" class="btn btn-md btn-primary">들어가기</a></p>
						</div>

					</div>	
					
				</div>
			</div>

			</div>

		</div>
	</div>


<jsp:include page="common/footer.jsp"></jsp:include>


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