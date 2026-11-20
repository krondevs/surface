package main

import (
	"time"

	"gorm.io/gorm/clause"
)

const (
	peerStatusVerified   = "verified"
	peerStatusUnverified = "unverified"
	peerStatusBanned     = "banned"
)

func (r *Registry) UpsertPeer(peer NodePeer) error {
	now := time.Now()
	if peer.FirstSeen.IsZero() {
		peer.FirstSeen = now
	}
	if peer.LastSeen.IsZero() {
		peer.LastSeen = now
	}
	if peer.ExpiresAt.IsZero() {
		peer.ExpiresAt = now.Add(peerTTL)
	}
	return r.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "public_key"}},
		DoUpdates: clause.Assignments(map[string]any{
			"address":     peer.Address,
			"status":      peer.Status,
			"source":      peer.Source,
			"last_seen":   peer.LastSeen,
			"last_verify": peer.LastVerify,
			"failures":    peer.Failures,
			"expires_at":  peer.ExpiresAt,
			"deleted_at":  nil,
		}),
	}).Create(&peer).Error
}

func (r *Registry) FindPeer(publicKey string) (*NodePeer, error) {
	var peer NodePeer
	if err := r.db.Where("public_key = ?", publicKey).First(&peer).Error; err != nil {
		return nil, err
	}
	return &peer, nil
}

func (r *Registry) ListPeers(limit int, verifiedOnly bool) ([]NodePeer, error) {
	if limit <= 0 || limit > peerListMax {
		limit = peerListMax
	}
	query := r.db.Where("expires_at > ?", time.Now())
	if verifiedOnly {
		query = query.Where("status = ?", peerStatusVerified)
	}
	peers := []NodePeer{}
	err := query.Order("last_seen desc").Limit(limit).Find(&peers).Error
	return peers, err
}

func (r *Registry) MarkPeerFailure(publicKey string) error {
	peer, err := r.FindPeer(publicKey)
	if err != nil {
		return err
	}
	peer.Failures++
	peer.Status = peerStatusUnverified
	peer.ExpiresAt = time.Now().Add(time.Hour)
	return r.UpsertPeer(*peer)
}

func (r *Registry) DeletePeer(publicKey string) error {
	return r.db.Unscoped().Where("public_key = ?", publicKey).Delete(&NodePeer{}).Error
}

func (r *Registry) ExpirePeers(now time.Time) (int64, error) {
	result := r.db.Unscoped().Where("expires_at < ?", now).Delete(&NodePeer{})
	return result.RowsAffected, result.Error
}

func (r *Registry) CountPeers(verifiedOnly bool) (int64, error) {
	query := r.db.Model(&NodePeer{}).Where("expires_at > ?", time.Now())
	if verifiedOnly {
		query = query.Where("status = ?", peerStatusVerified)
	}
	var count int64
	err := query.Count(&count).Error
	return count, err
}
