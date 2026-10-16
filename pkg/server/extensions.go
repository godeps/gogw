package server

// AddShutdownHook registers a callback before Start. Hooks run before listeners
// drain, allowing co-deployed components to withdraw application readiness.
func (s *Server) AddShutdownHook(hook func()) { s.shutdownHooks = append(s.shutdownHooks, hook) }
