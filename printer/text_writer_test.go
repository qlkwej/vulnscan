package printer

import "testing"

func TestTextWriter(t *testing.T) {
	s0, s1 := "- Hi, my name is Sullivan", "- Nice to meet you, Sullivan"
	tw := new(TextWriter)
	_, err := tw.Write([]byte(s0))
	_, err = tw.Write([]byte(s1))
	if err != nil {
		t.Errorf("Failed with error %s", err)
	}
	if tw0 := string(tw.inner[0]); tw0 != s0 {
		t.Errorf("printed strings differ: expected %s, got %s", tw0, s0)
	} else if tw1 := string(tw.inner[1]); tw1 != s1 {
		t.Errorf("printed strings differ: expected %s, got %s", tw1, s1)
	}
}
