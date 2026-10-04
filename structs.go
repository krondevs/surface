package main

import (
	"time"

	"gorm.io/gorm"
)

type Service struct {
	gorm.Model
	Name        string    `gorm:"column:name;index;uniqueIndex:idx_name_port" json:"name"`
	PublicKey   string    `gorm:"column:public_key;index" json:"public_key"`
	VirtualPort int       `gorm:"column:virtual_port;uniqueIndex:idx_name_port" json:"virtual_port"`
	Status      string    `gorm:"column:status;index" json:"status"`
	SessionID   string    `gorm:"column:session_id" json:"session_id"`
	LastSeen    time.Time `gorm:"column:last_seen;index" json:"last_seen"`
}

type NodeKey struct {
	gorm.Model
	Name      string `gorm:"column:name;index" json:"name"`
	PublicKey string `gorm:"column:public_key;uniqueIndex" json:"public_key"`
	Role      string `gorm:"column:role;index" json:"role"`
	Enabled   bool   `gorm:"column:enabled;index" json:"enabled"`
}
