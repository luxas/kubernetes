package reload

import (
	"k8s.io/kubernetes/pkg/util/filesystem"

	"github.com/fsnotify/fsnotify"
)

type ConfigWatcher interface {
	Run()
}

type configWatcher struct {
	watcher filesystem.FSWatcher
	errCh chan error
}

// NewConfigWatcher watches a config file, and sends an error to the channel when it changes
func NewConfigWatcher(file string, errCh chan error) (ConfigWatcher, error) {
	if errCh == nil {
		return nil, fmt.Errorf("errCh must not be nil")
	}
	cw := &configWatcher{
		watcher: filesystem.NewFsnotifyWatcher(),
		errCh: errCh,
	}
	if err := cw.watcher.Init(cw.eventHandler, cw.errorHandler); err != nil {
		return nil, err
	}
	if err := cw.watcher.AddWatch(file); err != nil {
		return nil, err
	}
	return cw, nil
}

func (cw *configWatcher) eventHandler(ent fsnotify.Event) {
	eventOpIs := func(Op fsnotify.Op) bool {
		return ent.Op&Op == Op
	}
	if eventOpIs(fsnotify.Write) || eventOpIs(fsnotify.Rename) {
		// error out when ConfigFile is updated
		o.errCh <- fmt.Errorf("content of the proxy server's configuration file was updated")
	}
}

func (cw *configWatcher) errorHandler(err error) {
	o.errCh <- err
}

func (cw *configWatcher) Run() {
	cw.watcher.Run()
}
