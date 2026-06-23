package sign_test

import (
	"fmt"

	"github.com/gtkit/encry/sign"
)

func ExampleSortByDic() {
	fmt.Println(sign.SortByDic(map[string]any{"a": "1", "b": 2}, "&"))
	// Output: a1&b2
}
