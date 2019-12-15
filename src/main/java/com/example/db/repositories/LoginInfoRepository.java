package com.example.db.repositories;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.example.db.dto.LoginInfo;

@Repository
public interface LoginInfoRepository extends CrudRepository<LoginInfo, Integer> {

	LoginInfo findByLoginName(String loginName);
}
