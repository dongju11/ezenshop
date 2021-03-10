package com.ezen.Service;

import java.util.List;

import javax.inject.Inject;

import org.springframework.stereotype.Repository;

import com.ezen.Vo.ASVO;
import com.ezen.Dao.ASDAO;
import com.ezen.Other.Criteria;

@Repository
public class ASServiceImpl implements ASService
{
	@Inject
	private ASDAO dao;
	
	@Override
	public void see() throws Exception{
		dao.see();
	}
	@Override
	public void write(ASVO vo) throws Exception{
		dao.write(vo);
	}
	
	@Override
	public ASVO read(int as_no) throws Exception{
		return dao.read(as_no);
	}
	
	@Override
	public void update(ASVO vo) throws Exception{
		dao.update(vo);
	}
	
	@Override
	public void delete(int as_no) throws Exception{
		dao.delete(as_no);
	}
	
	@Override
	public List<ASVO> list(Criteria cri) throws Exception{
		return dao.list(cri);
	}
	
	@Override
	public int listCount() throws Exception{
		return dao.listCount();
	}
}
