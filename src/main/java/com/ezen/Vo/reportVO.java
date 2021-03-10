package com.ezen.Vo;

import java.util.Date;

import org.springframework.web.multipart.MultipartFile;

public class reportVO {

	/*
	report_no number not null
	report_content varchar2(400) not null
	report_image varchar2(1000) 
	report_hitcount number default '0'
	report_title varchar2(100) not null
	report_regdate varchar2
	memeber_id  varchar2(20)  not null //작성자 
	boardcate varchar2(20) //카테고리
	
	CREATE SEQUENCE REPORT_NO_SEQ 
	START WITH 1 
	INCREMENT BY 1
	NOMAXVALUE
	MINVALUE 1;  
	 */
	
	private int report_no;
	private String report_content;
	private int report_hitcount;
	private String report_title;
	private Date report_regdate;
	private String member_id;
	private MultipartFile uploadFile;
	private String boardcate;
	
	public int getReport_no() {
		return report_no;
	}
	public void setReport_no(int report_no) {
		this.report_no = report_no;
	}
	public String getReport_content() {
		return report_content;
	}
	public void setReport_content(String report_content) {
		this.report_content = report_content;
	}
	public int getReport_hitcount() {
		return report_hitcount;
	}
	public void setReport_hitcount(int report_hitcount) {
		this.report_hitcount = report_hitcount;
	}
	public String getReport_title() {
		return report_title;
	}
	public void setReport_title(String report_title) {
		this.report_title = report_title;
	}
	public Date getReport_regdate() {
		return report_regdate;
	}
	public void setReport_regdate(Date report_regdate) {
		this.report_regdate = report_regdate;
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
	public String getBoardcate() {
		return boardcate;
	}
	public void setBoardcate(String boardcate) {
		this.boardcate = boardcate;
	}
	@Override
	public String toString() {
		return "reportVO [report_no=" + report_no + ", report_content=" + report_content + ", report_hitcount="
				+ report_hitcount + ", report_title=" + report_title + ", report_regdate=" + report_regdate
				+ ", member_id=" + member_id + ", uploadFile=" + uploadFile + ", boardcate=" + boardcate + "]";
	}
	
	
	
}
