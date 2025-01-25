package main

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"time"
)

// 规则文件直接存到数据库
func InitGorm() *gorm.DB {
	dsn := "root:root@tcp(127.0.0.1:3306)/rule_db?charset=utf8mb4&parseTime=True&loc=Local"

	var mysqlLogger logger.Interface
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger:                                   mysqlLogger,
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		logrus.Error(fmt.Sprintf("[%s] mysql连接失败", dsn))
		panic(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxIdleConns(10)               // 最大空闲连接数
	sqlDB.SetMaxOpenConns(100)              // 最多可容纳
	sqlDB.SetConnMaxLifetime(time.Hour * 4) // 连接最大复用时间，不能超过mysql的wait_timeout
	return db
}

func main() {
	db := InitGorm()
	db.AutoMigrate(&gormadapter.CasbinRule{})

	a, _ := gormadapter.NewAdapterByDB(db)
	m, err := model.NewModelFromFile("model.pml")
	if err != nil {
		logrus.Error("字符串加载模型失败!", err)
		return
	}
	e, _ := casbin.NewCachedEnforcer(m, a)
	e.SetExpireTime(60 * 60)
	_ = e.LoadPolicy()

	e.AddPolicy("admin", "/api/users", "GET")
	e.AddRoleForUser("zhangsan", "admin")
	check(e, "zhangsan", "/api/users", "GET")
	e.RemoveGroupingPolicy("zhangsan", "admin")
	e.RemovePolicy("admin", "/api/users", "GET")
	check(e, "zhangsan", "/api/users", "GET")
	e.SavePolicy()
	check(e, "zhangsan", "/api/users", "GET")
}

func check(e *casbin.CachedEnforcer, sub, obj, act string) {
	ok, _ := e.Enforce(sub, obj, act)
	if ok {
		fmt.Printf("%s CAN %s %s\n", sub, act, obj)
	} else {
		fmt.Printf("%s CANNOT %s %s\n", sub, act, obj)
	}
}
