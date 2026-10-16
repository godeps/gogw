package service

// AddServiceBuilder registers an explicitly constructed extension before routing
// starts. Builders return nil for names they do not own; runtime mutation is not
// supported, so ordinary service construction needs no extra synchronization.
func (f *ManagerFactory) AddServiceBuilder(builder ServiceBuilder) {
	f.extraBuilders = append(f.extraBuilders, builder)
}
