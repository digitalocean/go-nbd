package nbd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

const megabyte uint64 = 1024 * 1024

var nbdkitBin = func(defaultValue string) string {
	if v := os.Getenv("NBDKIT"); v != "" {
		return v
	}
	return defaultValue
}("nbdkit")

func provideNBDUnix(name string, size uint64) (wait func(), err error) {
	return nbdkitUnix(name, size)
}

func nbdkitUnix(name string, size uint64) (wait func(), err error) {
	args := []string{
		"--exit-with-parent",
		"-U",
		name,
		"memory",
		fmt.Sprintf("%dM", size/megabyte),
	}

	wait, err = nbdkit(args)
	if err != nil {
		return wait, err
	}

	for {
		_, err := os.Stat(name)
		if err == nil {
			break
		}
		if os.IsNotExist(err) {
			time.Sleep(100 * time.Millisecond)
			continue
		}
	}

	return wait, nil
}

func nbdkit(args []string) (wait func(), err error) {
	wait = func() {}

	ctx, cancel := context.WithCancel(context.Background())
	_ = cancel // Just to appease the 'lostcancel' lint failure

	cmd := exec.CommandContext(ctx, nbdkitBin, args...)
	err = cmd.Start()
	if err != nil {
		return wait, fmt.Errorf("start nbdkit %v: %w", args, err)
	}

	wait = func() {
		cancel()
		_ = cmd.Wait()
	}

	return wait, nil
}
