// ACL

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
	e, err := casbin.NewEnforcer("demo/model.pml", "demo/policy.csv")
	if err != nil {
		log.Fatalf("NewEnforecer failed:%v\n", err)
	}

	check(e, "zhangsan", "/index", "GET")
	check(e, "zhangsan", "/home", "GET")
	check(e, "zhangsan", "/users", "POST")

	// 新增一条规则
	//e.AddPolicy("wangwu", "/users", "POST")
	e.RemovePolicy("wangwu", "/users", "POST")
	e.SavePolicy() // 落库

	check(e, "wangwu", "/users", "POST")
}
