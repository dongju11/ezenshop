package com.ezen.Vo;

import java.util.Date;

import org.springframework.web.multipart.MultipartFile;

public class qnaVO {

	private int qna_no;
	private String qna_content;
	private String qna_title;
	private Date qna_date;
	private int qna_count;
	private String member_id;
	private String qnacate;
	private MultipartFile uploadFile;
	
	public int getQna_no() {
		return qna_no;
	}
	public void setQna_no(int qna_no) {
		this.qna_no = qna_no;
	}
	public String getQna_content() {
		return qna_content;
	}
	public void setQna_content(String qna_content) {
		this.qna_content = qna_content;
	}
	public String getQna_title() {
		return qna_title;
	}
	public void setQna_title(String qna_title) {
		this.qna_title = qna_title;
	}
	public Date getQna_date() {
		return qna_date;
	}
	public void setQna_date(Date qna_date) {
		this.qna_date = qna_date;
	}
	public int getQna_count() {
		return qna_count;
	}
	public void setQna_count(int qna_count) {
		this.qna_count = qna_count;
	}
	public String getMember_id() {
		return member_id;
	}
	public void setMember_id(String member_id) {
		this.member_id = member_id;
	}
	public String getQnacate() {
		return qnacate;
	}
	public void setQnacate(String qnacate) {
		this.qnacate = qnacate;
	}
	public MultipartFile getUploadFile() {
		return uploadFile;
	}
	public void setUploadFile(MultipartFile uploadFile) {
		this.uploadFile = uploadFile;
	}
	
	@Override
	public String toString() {
		return "qnaVO [qna_no=" + qna_no + ", qna_content=" + qna_content + ", qna_title=" + qna_title + ", qna_date="
				+ qna_date + ", qna_count=" + qna_count + ", member_id=" + member_id + ", qnacate=" + qnacate
				+ ", uploadFile=" + uploadFile + "]";
	}
	
}
