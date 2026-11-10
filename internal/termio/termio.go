// Package termio is how the Agent's interactive commands read the person at
// the terminal: one line at a time, ended by Ctrl+C as a shell would end it.
package termio

import (
	"bufio"
	"os"
	"os/signal"
	"syscall"
)

// ReadLine reads one line from r, or ends the process the way Ctrl+C ends a
// program that does not catch it. The Agent's commands cancel their work on
// SIGINT (signal.NotifyContext in main), and a read blocked on a terminal does
// not see that cancellation, so without this Ctrl+C at a prompt was swallowed
// and the command went on to its next question.
func ReadLine(r *bufio.Reader) (string, error) {
	type result struct {
		line string
		err  error
	}
	got := make(chan result, 1)
	interrupted := make(chan os.Signal, 1)
	signal.Notify(interrupted, os.Interrupt)
	defer signal.Stop(interrupted)
	go func() {
		line, err := r.ReadString('\n')
		got <- result{line, err}
	}()
	select {
	case res := <-got:
		return res.line, res.err
	case <-interrupted:
		dieOfInterrupt()
		return "", nil // not reached
	}
}

// dieOfInterrupt ends the process by SIGINT itself, so its parent (the
// installer, a shell) sees it killed by the signal, exit status 130, rather
// than an exit the program chose.
func dieOfInterrupt() {
	signal.Reset(os.Interrupt)
	_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
	select {}
}
