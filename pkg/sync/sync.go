package sync

func Callback(notify chan struct{}, fn func()) {
	fn()
	<-notify
}
