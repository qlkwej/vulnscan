package logrus

type TextWriter struct {
	inner []string
}

func (w *TextWriter) Write(p []byte) (n int, err error) {
	w.inner = append(w.inner, string(p))
	return len(p), nil
}
