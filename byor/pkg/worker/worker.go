package worker

import (
	"sync"
)

// Job represents a job to be executed, which is a file path.
type Job string

// Worker manages a pool of workers to execute jobs.
type Pool struct {
	jobs    chan Job
	results chan error
	wg      sync.WaitGroup
	workers int
	action  func(job Job) error
}

// New creates a new worker pool.
func New(workers int, action func(job Job) error) *Pool {
	return &Pool{
		jobs:    make(chan Job),
		results: make(chan error),
		workers: workers,
		action:  action,
	}
}

// Run starts the worker pool.
func (p *Pool) Run() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}

	go func() {
		p.wg.Wait()
		close(p.results)
	}()
}

// worker is the actual worker goroutine.
func (p *Pool) worker() {
	defer p.wg.Done()
	for job := range p.jobs {
		err := p.action(job)
		p.results <- err
	}
}

// AddJob adds a job to the pool.
func (p *Pool) AddJob(job Job) {
	p.jobs <- job
}

// CloseJobs closes the jobs channel.
func (p *Pool) CloseJobs() {
	close(p.jobs)
}

// Results returns the channel of results.
func (p *Pool) Results() <-chan error {
	return p.results
}
