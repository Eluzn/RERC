package monitoring

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"sync"
	"time"
)

// Metrics holds various performance and security metrics
type Metrics struct {
	// Connection metrics
	ActiveConnections    int64     `json:"active_connections"`
	TotalConnections     int64     `json:"total_connections"`
	FailedConnections    int64     `json:"failed_connections"`
	
	// Message metrics
	MessagesProcessed    int64     `json:"messages_processed"`
	MessagesRelayed      int64     `json:"messages_relayed"`
	MessagesFailed       int64     `json:"messages_failed"`
	EncryptionOperations int64     `json:"encryption_operations"`
	DecryptionOperations int64     `json:"decryption_operations"`
	
	// Security metrics
	AuthenticationAttempts int64   `json:"auth_attempts"`
	AuthenticationFailures int64   `json:"auth_failures"`
	InvalidSignatures      int64   `json:"invalid_signatures"`
	ReplayAttempts         int64   `json:"replay_attempts"`
	
	// Performance metrics
	AverageLatency         float64 `json:"avg_latency_ms"`
	PeakLatency           float64 `json:"peak_latency_ms"`
	Throughput            float64 `json:"throughput_msg_per_sec"`
	
	// System metrics
	MemoryUsageMB         float64 `json:"memory_usage_mb"`
	CPUUsagePercent       float64 `json:"cpu_usage_percent"`
	GoroutineCount        int     `json:"goroutine_count"`
	
	// Time tracking
	StartTime             time.Time `json:"start_time"`
	LastUpdated           time.Time `json:"last_updated"`
	
	mu sync.RWMutex
}

// Monitor handles metrics collection and monitoring
type Monitor struct {
	metrics    *Metrics
	alerts     []Alert
	thresholds Thresholds
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.RWMutex
}

// Alert represents a monitoring alert
type Alert struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Message     string    `json:"message"`
	Timestamp   time.Time `json:"timestamp"`
	Acknowledged bool     `json:"acknowledged"`
}

// Thresholds defines monitoring thresholds
type Thresholds struct {
	MaxMemoryMB           float64
	MaxCPUPercent         float64
	MaxConnections        int64
	MaxLatencyMS          float64
	MaxFailureRate        float64
	MaxInvalidSignatures  int64
}

// NewMonitor creates a new monitoring instance
func NewMonitor() *Monitor {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &Monitor{
		metrics: &Metrics{
			StartTime:   time.Now(),
			LastUpdated: time.Now(),
		},
		alerts:     make([]Alert, 0),
		thresholds: getDefaultThresholds(),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start begins the monitoring routines
func (m *Monitor) Start() {
	go m.collectSystemMetrics()
	go m.checkThresholds()
}

// Stop stops all monitoring routines
func (m *Monitor) Stop() {
	m.cancel()
}

// IncrementConnections increments connection counters
func (m *Monitor) IncrementConnections() {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()
	
	m.metrics.ActiveConnections++
	m.metrics.TotalConnections++
	m.metrics.LastUpdated = time.Now()
}

// DecrementConnections decrements active connections
func (m *Monitor) DecrementConnections() {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()
	
	if m.metrics.ActiveConnections > 0 {
		m.metrics.ActiveConnections--
	}
	m.metrics.LastUpdated = time.Now()
}

// RecordFailedConnection records a failed connection attempt
func (m *Monitor) RecordFailedConnection() {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()
	
	m.metrics.FailedConnections++
	m.metrics.LastUpdated = time.Now()
}

// RecordMessageProcessed records a processed message
func (m *Monitor) RecordMessageProcessed() {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()
	
	m.metrics.MessagesProcessed++
	m.metrics.LastUpdated = time.Now()
}

// RecordMessageRelayed records a relayed message
func (m *Monitor) RecordMessageRelayed() {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()
	
	m.metrics.MessagesRelayed++
	m.metrics.LastUpdated = time.Now()
}

// RecordMessageFailed records a failed message
func (m *Monitor) RecordMessageFailed() {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()
	
	m.metrics.MessagesFailed++
	m.metrics.LastUpdated = time.Now()
}

// RecordEncryption records an encryption operation
func (m *Monitor) RecordEncryption() {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()
	
	m.metrics.EncryptionOperations++
	m.metrics.LastUpdated = time.Now()
}

// RecordDecryption records a decryption operation
func (m *Monitor) RecordDecryption() {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()
	
	m.metrics.DecryptionOperations++
	m.metrics.LastUpdated = time.Now()
}

// RecordAuthAttempt records an authentication attempt
func (m *Monitor) RecordAuthAttempt() {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()
	
	m.metrics.AuthenticationAttempts++
	m.metrics.LastUpdated = time.Now()
}

// RecordAuthFailure records an authentication failure
func (m *Monitor) RecordAuthFailure() {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()
	
	m.metrics.AuthenticationFailures++
	m.metrics.LastUpdated = time.Now()
}

// RecordInvalidSignature records an invalid signature
func (m *Monitor) RecordInvalidSignature() {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()
	
	m.metrics.InvalidSignatures++
	m.metrics.LastUpdated = time.Now()
}

// RecordReplayAttempt records a replay attack attempt
func (m *Monitor) RecordReplayAttempt() {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()
	
	m.metrics.ReplayAttempts++
	m.metrics.LastUpdated = time.Now()
}

// RecordLatency records message processing latency
func (m *Monitor) RecordLatency(latency time.Duration) {
	latencyMS := float64(latency.Nanoseconds()) / 1e6
	
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()
	
	// Simple moving average (in production, use more sophisticated approach)
	if m.metrics.AverageLatency == 0 {
		m.metrics.AverageLatency = latencyMS
	} else {
		m.metrics.AverageLatency = (m.metrics.AverageLatency + latencyMS) / 2
	}
	
	if latencyMS > m.metrics.PeakLatency {
		m.metrics.PeakLatency = latencyMS
	}
	
	m.metrics.LastUpdated = time.Now()
}

// GetMetrics returns a copy of current metrics
func (m *Monitor) GetMetrics() Metrics {
	m.metrics.mu.RLock()
	defer m.metrics.mu.RUnlock()
	
	return *m.metrics
}

// GetAlerts returns current alerts
func (m *Monitor) GetAlerts() []Alert {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	alerts := make([]Alert, len(m.alerts))
	copy(alerts, m.alerts)
	return alerts
}

// collectSystemMetrics collects system-level metrics
func (m *Monitor) collectSystemMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.updateSystemMetrics()
		}
	}
}

// updateSystemMetrics updates system metrics
func (m *Monitor) updateSystemMetrics() {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()
	
	m.metrics.MemoryUsageMB = float64(mem.Alloc) / 1024 / 1024
	m.metrics.GoroutineCount = runtime.NumGoroutine()
	
	// Calculate throughput (messages per second)
	elapsed := time.Since(m.metrics.StartTime).Seconds()
	if elapsed > 0 {
		m.metrics.Throughput = float64(m.metrics.MessagesProcessed) / elapsed
	}
	
	m.metrics.LastUpdated = time.Now()
}

// checkThresholds monitors for threshold violations
func (m *Monitor) checkThresholds() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.evaluateThresholds()
		}
	}
}

// evaluateThresholds checks if any thresholds are exceeded
func (m *Monitor) evaluateThresholds() {
	metrics := m.GetMetrics()
	
	// Check memory usage
	if metrics.MemoryUsageMB > m.thresholds.MaxMemoryMB {
		m.addAlert("HIGH_MEMORY", "critical", 
			fmt.Sprintf("Memory usage %.2f MB exceeds threshold %.2f MB", 
				metrics.MemoryUsageMB, m.thresholds.MaxMemoryMB))
	}
	
	// Check connection count
	if metrics.ActiveConnections > m.thresholds.MaxConnections {
		m.addAlert("HIGH_CONNECTIONS", "warning", 
			fmt.Sprintf("Active connections %d exceeds threshold %d", 
				metrics.ActiveConnections, m.thresholds.MaxConnections))
	}
	
	// Check latency
	if metrics.AverageLatency > m.thresholds.MaxLatencyMS {
		m.addAlert("HIGH_LATENCY", "warning", 
			fmt.Sprintf("Average latency %.2f ms exceeds threshold %.2f ms", 
				metrics.AverageLatency, m.thresholds.MaxLatencyMS))
	}
	
	// Check failure rate
	totalMessages := metrics.MessagesProcessed + metrics.MessagesFailed
	if totalMessages > 0 {
		failureRate := float64(metrics.MessagesFailed) / float64(totalMessages)
		if failureRate > m.thresholds.MaxFailureRate {
			m.addAlert("HIGH_FAILURE_RATE", "critical", 
				fmt.Sprintf("Message failure rate %.2f%% exceeds threshold %.2f%%", 
					failureRate*100, m.thresholds.MaxFailureRate*100))
		}
	}
	
	// Check security metrics
	if metrics.InvalidSignatures > m.thresholds.MaxInvalidSignatures {
		m.addAlert("SECURITY_THREAT", "critical", 
			fmt.Sprintf("Invalid signatures %d exceeds threshold %d", 
				metrics.InvalidSignatures, m.thresholds.MaxInvalidSignatures))
	}
	
	if metrics.ReplayAttempts > 0 {
		m.addAlert("REPLAY_ATTACK", "critical", 
			fmt.Sprintf("Detected %d replay attack attempts", metrics.ReplayAttempts))
	}
}

// addAlert adds a new alert
func (m *Monitor) addAlert(alertType, severity, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	alert := Alert{
		ID:        fmt.Sprintf("%s-%d", alertType, time.Now().Unix()),
		Type:      alertType,
		Severity:  severity,
		Message:   message,
		Timestamp: time.Now(),
	}
	
	m.alerts = append(m.alerts, alert)
	log.Printf("ALERT [%s]: %s", severity, message)
	
	// Keep only last 100 alerts
	if len(m.alerts) > 100 {
		m.alerts = m.alerts[len(m.alerts)-100:]
	}
}

// getDefaultThresholds returns default monitoring thresholds
func getDefaultThresholds() Thresholds {
	return Thresholds{
		MaxMemoryMB:          50.0,   // 50MB
		MaxCPUPercent:        80.0,   // 80%
		MaxConnections:       1000,   // 1000 connections
		MaxLatencyMS:         500.0,  // 500ms
		MaxFailureRate:       0.05,   // 5%
		MaxInvalidSignatures: 10,     // 10 invalid signatures
	}
}

// SecurityAudit performs a security audit and returns findings
func (m *Monitor) SecurityAudit() map[string]interface{} {
	metrics := m.GetMetrics()
	
	audit := map[string]interface{}{
		"timestamp": time.Now(),
		"findings": map[string]interface{}{
			"authentication": map[string]interface{}{
				"total_attempts": metrics.AuthenticationAttempts,
				"failures":       metrics.AuthenticationFailures,
				"failure_rate":   float64(metrics.AuthenticationFailures) / float64(metrics.AuthenticationAttempts),
			},
			"encryption": map[string]interface{}{
				"operations":        metrics.EncryptionOperations + metrics.DecryptionOperations,
				"invalid_signatures": metrics.InvalidSignatures,
				"replay_attempts":   metrics.ReplayAttempts,
			},
			"performance": map[string]interface{}{
				"memory_usage_mb": metrics.MemoryUsageMB,
				"avg_latency_ms":  metrics.AverageLatency,
				"peak_latency_ms": metrics.PeakLatency,
				"goroutines":      metrics.GoroutineCount,
			},
		},
		"recommendations": m.generateRecommendations(metrics),
	}
	
	return audit
}

// generateRecommendations generates security and performance recommendations
func (m *Monitor) generateRecommendations(metrics Metrics) []string {
	var recommendations []string
	
	if metrics.MemoryUsageMB > 40 {
		recommendations = append(recommendations, "Consider implementing memory optimization or increasing available memory")
	}
	
	if metrics.AverageLatency > 200 {
		recommendations = append(recommendations, "High latency detected - consider optimizing cryptographic operations or network configuration")
	}
	
	if metrics.InvalidSignatures > 5 {
		recommendations = append(recommendations, "Multiple invalid signatures detected - potential security threat")
	}
	
	if metrics.ReplayAttempts > 0 {
		recommendations = append(recommendations, "Replay attacks detected - ensure proper timestamp validation")
	}
	
	failureRate := float64(metrics.MessagesFailed) / float64(metrics.MessagesProcessed + metrics.MessagesFailed)
	if failureRate > 0.02 {
		recommendations = append(recommendations, "High message failure rate - investigate network or cryptographic issues")
	}
	
	return recommendations
}
