package com.ezen.Vo;

import java.util.Date;

public class CommentVO {

	
	/*
	    comments_no number not null
		review_no number 
		fr_no number 
		qna_no number 
		report_no number 
		notice_no number 
		member_no number 
		comments_writer varchar2(20) not null
		comments_content varchar2(4000) not null
		comments_date date 湲곕낯媛뭩ysdate
		
		comments_seq �떆���뒪
	 */
	
	private int comments_no;
	private int fr_no;
	private int qna_no;
	private int report_no;
	private int notice_no;
	private String comments_writer;
	private String comments_content;
	private Date comments_date;
	public int getComments_no() {
		return comments_no;
	}
	public void setComments_no(int comments_no) {
		this.comments_no = comments_no;
	}

	public int getFr_no() {
		return fr_no;
	}
	public void setFr_no(int fr_no) {
		this.fr_no = fr_no;
	}
	public int getQna_no() {
		return qna_no;
	}
	public void setQna_no(int qna_no) {
		this.qna_no = qna_no;
	}
	public int getReport_no() {
		return report_no;
	}
	public void setReport_no(int report_no) {
		this.report_no = report_no;
	}
	public int getNotice_no() {
		return notice_no;
	}
	public void setNotice_no(int notice_no) {
		this.notice_no = notice_no;
	}

	public String getComments_writer() {
		return comments_writer;
	}
	public void setComments_writer(String comments_writer) {
		this.comments_writer = comments_writer;
	}
	public String getComments_content() {
		return comments_content;
	}
	public void setComments_content(String comments_content) {
		this.comments_content = comments_content;
	}
	public Date getComments_date() {
		return comments_date;
	}
	public void setComments_date(Date comments_date) {
		this.comments_date = comments_date;
	}
	@Override
	public String toString() {
		return "CommentVO [comments_no=" + comments_no + ", fr_no=" + fr_no + ", qna_no=" + qna_no + ", report_no="
				+ report_no + ", notice_no=" + notice_no + ", comments_writer=" + comments_writer
				+ ", comments_content=" + comments_content + ", comments_date=" + comments_date + "]";
	}
	
	
	
}