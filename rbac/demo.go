// RBAC

package main

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	"log"
)

func check(e *casbin.Enforcer, sub, obj, act string) {
	ok, _ := e.Enforce(sub, obj, act)
	if ok {
		fmt.Printf("%s CAN %s %s\n", sub, act, obj)
	} else {
		fmt.Printf("%s CANNOT %s %s\n", sub, act, obj)
	}
}

func main() {
	e, err := casbin.NewEnforcer("rbac/model.pml", "rbac/policy.csv")
	if err != nil {
		log.Fatalf("NewEnforecer failed:%v\n", err)
	}

	check(e, "zhangsan", "/index", "GET")
	check(e, "zhangsan", "/home", "GET")
	check(e, "zhangsan", "/users", "POST")

	// 新增一条规则
	//e.AddPolicy("admin", "/users", "DELETE")
	//e.SavePolicy() // 落库

	// 新增一个用户role
	e.AddRoleForUser("wangwu", "admin")
	e.SavePolicy()

	check(e, "wangwu", "/users", "POST")
}
