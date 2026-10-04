package main

import (
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	statusOnline  = "online"
	statusOffline = "offline"
)

var errServiceNotFound = errors.New("service not found or offline")

type Registry struct {
	db *gorm.DB
}

func NewRegistry(db *gorm.DB) *Registry {
	return &Registry{db: db}
}

func (r *Registry) UpsertService(name, publicKey string, virtualPort int, sessionID string) error {
	svc := Service{
		Name:        name,
		PublicKey:   publicKey,
		VirtualPort: virtualPort,
		Status:      statusOnline,
		SessionID:   sessionID,
		LastSeen:    time.Now(),
	}
	return r.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "name"}, {Name: "virtual_port"}},
		DoUpdates: clause.Assignments(map[string]any{
			"public_key": publicKey,
			"status":     statusOnline,
			"session_id": sessionID,
			"last_seen":  time.Now(),
			"deleted_at": nil,
		}),
	}).Create(&svc).Error
}

func (r *Registry) MarkSessionOffline(sessionID string) error {
	return r.db.Model(&Service{}).
		Where("session_id = ?", sessionID).
		Update("status", statusOffline).Error
}

func (r *Registry) Heartbeat(sessionID string) error {
	return r.db.Model(&Service{}).
		Where("session_id = ?", sessionID).
		Updates(map[string]any{"last_seen": time.Now(), "status": statusOnline}).Error
}

func (r *Registry) Lookup(name string, virtualPort int) (*Service, error) {
	var svc Service
	err := r.db.Where("name = ? AND virtual_port = ? AND status = ?", name, virtualPort, statusOnline).
		Order("id desc").First(&svc).Error
	if err != nil {
		return nil, errServiceNotFound
	}
	return &svc, nil
}

func (r *Registry) ListServices() ([]Service, error) {
	services := []Service{}
	err := r.db.Limit(200).Order("id desc").Find(&services).Error
	return services, err
}

func (r *Registry) CountOnlineServices() (int64, error) {
	var count int64
	err := r.db.Model(&Service{}).Where("status = ?", statusOnline).Count(&count).Error
	return count, err
}

func (r *Registry) UpsertNodeKey(name, publicKey, role string, enabled bool) error {
	key := NodeKey{Name: name, PublicKey: publicKey, Role: role, Enabled: enabled}
	return r.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "public_key"}},
		DoUpdates: clause.Assignments(map[string]any{"name": name, "role": role}),
	}).Create(&key).Error
}

func (r *Registry) FindNodeKey(publicKey string) (*NodeKey, error) {
	var key NodeKey
	if err := r.db.Where("public_key = ?", publicKey).First(&key).Error; err != nil {
		return nil, err
	}
	return &key, nil
}

func (r *Registry) SetNodeKeyEnabled(publicKey string, enabled bool) error {
	return r.db.Model(&NodeKey{}).
		Where("public_key = ?", publicKey).
		Update("enabled", enabled).Error
}

func (r *Registry) ListNodeKeys() ([]NodeKey, error) {
	keys := []NodeKey{}
	err := r.db.Limit(200).Order("id desc").Find(&keys).Error
	return keys, err
}
