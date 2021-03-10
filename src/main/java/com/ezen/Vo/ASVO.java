package com.ezen.Vo;

import java.util.Date;

/*
create table as_list(
as_no number not null, -- as번호
as_title varchar2(100) not null,--제목
as_content varchar2(4000) not null,--내용
as_writer varchhar2(50) not null, --작성자
as_account  number not null, --환불계좌
as_category varchar2(80) not null, --카테고리
as_regdate date not null default sysdate,--as신청날짜
constraint as_list_pk primary key(as_no) enable
);

create sequence as_no_seq
start with 1
increment by 1
nomaxvalue
minvalue 1;
*/
public class ASVO
{
	private int as_no;
	private String order_id;
	private String as_title;
	private String as_content;
	private String as_writer;
	private int as_account;
	private String as_category;
	private Date as_regdate;
	private String member_id;
	
	public int getAs_no() {
		return as_no;
	}
	public void setAs_no(int as_no) {
		this.as_no = as_no;
	}
	public String getOrder_id() {
		return order_id;
	}
	public void setOrder_id(String order_id) {
		this.order_id = order_id;
	}
	public String getAs_title() {
		return as_title;
	}
	public void setAs_title(String as_title) {
		this.as_title = as_title;
	}
	public String getAs_content() {
		return as_content;
	}
	public void setAs_content(String as_content) {
		this.as_content = as_content;
	}
	public String getAs_writer() {
		return as_writer;
	}
	public void setAs_writer(String as_writer) {
		this.as_writer = as_writer;
	}
	public int getAs_account() {
		return as_account;
	}
	public void setAs_account(int as_account) {
		this.as_account = as_account;
	}
	public String getAs_category() {
		return as_category;
	}
	public void setAs_category(String as_category) {
		this.as_category = as_category;
	}
	public Date getAs_regdate() {
		return as_regdate;
	}
	public void setAs_regdate(Date as_regdate) {
		this.as_regdate = as_regdate;
	}
	public String getMember_id() {
		return member_id;
	}
	public void setMember_id(String member_id) {
		this.member_id = member_id;
	}
	
	
}
