package sqids_test

import (
	"fmt"

	"github.com/gtkit/encry/sqids"
)

func ExampleNew() {
	h, err := sqids.New()
	if err != nil {
		panic(err)
	}
	id, err := h.Encode([]uint64{1, 2, 3})
	if err != nil {
		panic(err)
	}
	fmt.Println(h.Decode(id))
	// Output: [1 2 3]
}
