package outbound

import (
	"context"
	"os"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var (
	_ adapter.OutboundManager         = (*Manager)(nil)
	_ adapter.RuntimeComponentRemover = (*Manager)(nil)
	_ adapter.OutboundAdder           = (*Manager)(nil)
)

type Manager struct {
	mutation  sync.Mutex
	lifecycle *adapter.LifecycleGroup
	stage     adapter.StartStage

	registry                adapter.OutboundRegistry
	endpoint                adapter.EndpointManager
	defaultTag              string
	access                  sync.RWMutex
	outbounds               []adapter.Outbound
	outboundByTag           map[string]adapter.Outbound
	defaultOutbound         adapter.Outbound
	defaultOutboundFallback func() (adapter.Outbound, error)
}

func NewManager(registry adapter.OutboundRegistry, endpoint adapter.EndpointManager, defaultTag string) *Manager {
	return &Manager{
		registry:      registry,
		endpoint:      endpoint,
		defaultTag:    defaultTag,
		outboundByTag: make(map[string]adapter.Outbound),
	}
}

func (m *Manager) Initialize(defaultOutboundFallback func() (adapter.Outbound, error)) {
	m.defaultOutboundFallback = defaultOutboundFallback
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.mutation.Lock()
	defer m.mutation.Unlock()
	m.stage = stage
	if stage == adapter.StartStateInitialize {
		m.lifecycle = adapter.NewLifecycleGroup(scope)
	}
	m.access.Lock()
	if stage == adapter.StartStateInitialize {
		if m.defaultTag != "" && m.defaultOutbound == nil {
			defaultEndpoint, loaded := m.endpoint.Get(m.defaultTag)
			if !loaded {
				m.access.Unlock()
				return E.New("default outbound not found: ", m.defaultTag)
			}
			m.defaultOutbound = defaultEndpoint
		}
		if m.defaultOutbound == nil {
			directOutbound, err := m.defaultOutboundFallback()
			if err != nil {
				m.access.Unlock()
				return E.Cause(err, "create direct outbound for fallback")
			}
			m.outbounds = append(m.outbounds, directOutbound)
			m.outboundByTag[directOutbound.Tag()] = directOutbound
			m.defaultOutbound = directOutbound
		}
	}
	outbounds := m.outbounds
	m.access.Unlock()
	if stage == adapter.StartStateStart {
		return m.startOutbounds(scope, append(outbounds, common.Map(m.endpoint.Endpoints(), func(it adapter.Endpoint) adapter.Outbound { return it })...))
	}
	for _, outbound := range outbounds {
		lifecycle, isLifecycle := outbound.(adapter.Lifecycle)
		if !isLifecycle {
			continue
		}
		name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
		err := m.lifecycle.Start(name, lifecycle, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) startOutbounds(scope *adapter.Scope, outbounds []adapter.Outbound) error {
	started := make(map[string]bool)
	for {
		canContinue := false
	startOne:
		for _, outboundToStart := range outbounds {
			outboundTag := outboundToStart.Tag()
			if started[outboundTag] {
				continue
			}
			dependencies := outboundToStart.Dependencies()
			for _, dependency := range dependencies {
				if !started[dependency] {
					continue startOne
				}
			}
			started[outboundTag] = true
			canContinue = true
			if endpoint, isEndpoint := outboundToStart.(adapter.Endpoint); isEndpoint {
				err := m.endpoint.StartEndpoint(endpoint)
				if err != nil {
					return err
				}
				continue
			}
			lifecycle, isLifecycle := outboundToStart.(adapter.Lifecycle)
			if !isLifecycle {
				continue
			}
			name := "outbound/" + outboundToStart.Type() + "[" + outboundTag + "]"
			err := m.lifecycle.Start(name, lifecycle, adapter.StartStateStart)
			if err != nil {
				return err
			}
		}
		if len(started) == len(outbounds) {
			break
		}
		if canContinue {
			continue
		}
		currentOutbound := common.Find(outbounds, func(it adapter.Outbound) bool {
			return !started[it.Tag()]
		})
		var lintOutbound func(oTree []string, oCurrent adapter.Outbound) error
		lintOutbound = func(oTree []string, oCurrent adapter.Outbound) error {
			problemOutboundTag := common.Find(oCurrent.Dependencies(), func(it string) bool {
				return !started[it]
			})
			if common.Contains(oTree, problemOutboundTag) {
				return E.New("circular outbound dependency: ", strings.Join(oTree, " -> "), " -> ", problemOutboundTag)
			}
			problemOutbound := common.Find(outbounds, func(it adapter.Outbound) bool {
				return it.Tag() == problemOutboundTag
			})
			if problemOutbound == nil {
				return E.New("dependency[", problemOutboundTag, "] not found for outbound[", oCurrent.Tag(), "]")
			}
			return lintOutbound(append(oTree, problemOutboundTag), problemOutbound)
		}
		return lintOutbound([]string{currentOutbound.Tag()}, currentOutbound)
	}
	return nil
}

func (m *Manager) Outbounds() []adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return append([]adapter.Outbound(nil), m.outbounds...)
}

func (m *Manager) Outbound(tag string) (adapter.Outbound, bool) {
	m.access.RLock()
	outbound, found := m.outboundByTag[tag]
	m.access.RUnlock()
	if found {
		return outbound, true
	}
	return m.endpoint.Get(tag)
}

func (m *Manager) Default() adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.defaultOutbound
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, inboundType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}
	outbound, err := m.registry.CreateOutbound(ctx, router, logger, tag, inboundType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	_, loaded := m.outboundByTag[tag]
	if loaded {
		return E.New("duplicate outbound tag: ", tag)
	}
	m.outbounds = append(m.outbounds, outbound)
	m.outboundByTag[tag] = outbound
	if tag == m.defaultTag || (m.defaultTag == "" && m.defaultOutbound == nil) {
		m.defaultOutbound = outbound
	}
	return nil
}

// AddOutbound registers an outbound its owner constructed itself (the region
// views of a smart-loadbalance group). Going through Create from inside a
// constructor would re-enter the registry, which holds its lock while a
// constructor runs. Before the manager starts, a duplicate tag is an error and
// the outbound is started with the rest by Start; afterwards it is started as
// a runtime outbound and replaces any outbound with the same tag. A generated
// outbound only becomes the default outbound when route.final names it:
// owners register it before themselves, so it must not take the "first
// outbound" default from its owner.
func (m *Manager) AddOutbound(outbound adapter.Outbound) error {
	if outbound == nil || outbound.Tag() == "" {
		return os.ErrInvalid
	}
	m.mutation.Lock()
	defer m.mutation.Unlock()
	tag := outbound.Tag()
	runtimeStarted := m.lifecycle != nil
	if !runtimeStarted {
		m.access.RLock()
		_, loaded := m.outboundByTag[tag]
		m.access.RUnlock()
		if loaded {
			return E.New("duplicate outbound tag: ", tag)
		}
	} else if lifecycle, isLifecycle := outbound.(adapter.Lifecycle); isLifecycle {
		// Start before swapping, so a replaced outbound keeps serving until
		// its successor is ready.
		for _, stage := range adapter.ListStartStages {
			if stage > m.stage {
				break
			}
			if err := m.lifecycle.Start("outbound/"+outbound.Type()+"["+tag+"]", lifecycle, stage); err != nil {
				return E.Errors(err, m.lifecycle.Remove(lifecycle))
			}
		}
	}
	m.access.Lock()
	replaced := m.outboundByTag[tag]
	if replaced != nil {
		m.outbounds = common.Filter(m.outbounds, func(it adapter.Outbound) bool {
			return it != replaced
		})
	}
	m.outbounds = append(m.outbounds, outbound)
	m.outboundByTag[tag] = outbound
	if tag == m.defaultTag || (replaced != nil && m.defaultOutbound == replaced) {
		m.defaultOutbound = outbound
	}
	m.access.Unlock()
	if replaced != nil {
		if lifecycle, isLifecycle := replaced.(adapter.Lifecycle); isLifecycle && m.lifecycle != nil {
			return m.lifecycle.Remove(lifecycle)
		}
	}
	return nil
}

// Replace prepares a provider node before publishing it. Static Create retains
// its duplicate-tag validation.
func (m *Manager) Replace(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {
	m.mutation.Lock()
	defer m.mutation.Unlock()
	node, err := m.registry.CreateOutbound(ctx, router, logger, tag, outboundType, options)
	if err != nil {
		return err
	}
	if lifecycle, ok := node.(adapter.Lifecycle); ok && m.lifecycle != nil {
		for _, stage := range adapter.ListStartStages {
			if stage > m.stage {
				break
			}
			if err = m.lifecycle.Start("outbound/"+node.Type()+"["+tag+"]", lifecycle, stage); err != nil {
				return E.Errors(err, m.lifecycle.Remove(lifecycle))
			}
		}
	}
	m.access.Lock()
	old := m.outboundByTag[tag]
	if old == nil {
		m.outbounds = append(m.outbounds, node)
	} else {
		for i, item := range m.outbounds {
			if item == old {
				m.outbounds[i] = node
				break
			}
		}
	}
	m.outboundByTag[tag] = node
	if m.defaultOutbound == old && old != nil {
		m.defaultOutbound = node
	}
	m.access.Unlock()
	if lifecycle, ok := old.(adapter.Lifecycle); ok && m.lifecycle != nil {
		if closeErr := m.lifecycle.Remove(lifecycle); closeErr != nil {
			logger.Error(closeErr, "close replaced outbound ", tag)
		}
	}
	return nil
}

func (m *Manager) Remove(tag string) error {
	m.mutation.Lock()
	defer m.mutation.Unlock()
	m.access.Lock()
	old := m.outboundByTag[tag]
	if old == nil {
		m.access.Unlock()
		return nil
	}
	delete(m.outboundByTag, tag)
	for i, item := range m.outbounds {
		if item == old {
			m.outbounds = append(m.outbounds[:i], m.outbounds[i+1:]...)
			break
		}
	}
	if m.defaultOutbound == old {
		m.defaultOutbound = nil
		if len(m.outbounds) > 0 {
			m.defaultOutbound = m.outbounds[0]
		}
	}
	m.access.Unlock()
	if lifecycle, ok := old.(adapter.Lifecycle); ok && m.lifecycle != nil {
		return m.lifecycle.Remove(lifecycle)
	}
	return nil
}
