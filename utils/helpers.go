package utils


func I(n int) []struct{} {
return make([]struct{}, n)
}

func R(b, e int) chan int {
	ch := make(chan int)

	go func () {
		for i := b; i < e; i++ {
			ch <- i
		}
		close(ch)
	}()

	return ch
}

func RS(b, e, s int) chan int {
	ch := make(chan int)

	go func () {
		for i := b; i < e; i+=s {
			ch <- i
		}
		close(ch)
	}()

	return ch
}