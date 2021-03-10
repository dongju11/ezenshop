package com.ezen.Vo;

import java.util.Date;

import org.springframework.web.multipart.MultipartFile;


public class boardVO {
	/*
	 fr_no number not null, 
fr_title varchar2(100)  not null,
fr_content varchar2(3000) not null,
fr_date date
member_no number
fr_count number not null, 기본값 0
fr_image varchar2(20)
member_id varchar2(20) not null

CREATE SEQUENCE FR_NO_SEQ
 START WITH 1
 INCREMENT BY 1
 NOMAXVALUE
 MINVALUE 1;

ADD CONSTRAINT FREE_FK_1 FOREIGN KEY(MEMBER_NO) REFERENCES MEMBER (MEMBER_NO); //현재 해지상태 

테이블에 엑셀에  FOREIGN KEY_2 (MEMBER_ID) 안만듬
	 */
	
	private int fr_no;
	private String fr_title;
	private String fr_content;
	private Date fr_date;
//private int member_no;
	private int fr_count;
	private String member_id;
	private MultipartFile uploadFile;
	
	
	public int getFr_no() {
		return fr_no;
	}
	public void setFr_no(int fr_no) {
		this.fr_no = fr_no;
	}
	public String getFr_title() {
		return fr_title;
	}
	public void setFr_title(String fr_title) {
		this.fr_title = fr_title;
	}
	public String getFr_content() {
		return fr_content;
	}
	public void setFr_content(String fr_content) {
		this.fr_content = fr_content;
	}
	public Date getFr_date() {
		return fr_date;
	}
	public void setFr_date(Date fr_date) {
		this.fr_date = fr_date;
	}
	public int getFr_count() {
		return fr_count;
	}
	public void setFr_count(int fr_count) {
		this.fr_count = fr_count;
	}
	public String getMember_id() {
		return member_id;
	}
	public void setMember_id(String member_id) {
		this.member_id = member_id;
	}
	public MultipartFile getUploadFile() {
		return uploadFile;
	}
	public void setUploadFile(MultipartFile uploadFile) {
		this.uploadFile = uploadFile;
	}
	
	@Override
	public String toString() {
		return "boardVO [fr_no=" + fr_no + ", fr_title=" + fr_title + ", fr_content=" + fr_content + ", fr_date="
				+ fr_date + ", fr_count=" + fr_count + ", member_id=" + member_id
				+ ", uploadFile=" + uploadFile + "]";
	}

	
	
}
