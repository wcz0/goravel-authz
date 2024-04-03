package models

import (
	"github.com/goravel/framework/database/orm"
)

type Rule struct {
	orm.Model
	Id    uint
	PType string
	V0    string
	V1    string
	V2    string
	V3    string
	V4    string
	V5    string
}
