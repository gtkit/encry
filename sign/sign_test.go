// @Author xiaozhaofu 2023/3/20 17:56:00
package sign

import (
	"testing"
)

type OrderParams map[string]interface{}

func TestSortByDic(t *testing.T) {

	op := make(OrderParams)
	op["client_id"] = "9aff19ba86e547159d9f1ecc3c322fbb"
	op["access_token"] = "67703ba8c6f143a0834071f6c1372b3c2ff7090a"
	op["data_type"] = "JSON"
	op["order_status"] = 3
	op["page"] = 1
	op["page_size"] = 100
	op["timestamp"] = 1661947835
	op["order_status"] = 3
	op["end_updated_at"] = 1661930091
	op["start_updated_at"] = 1661931891
	op["is_lucky_flag"] = 0
	op["refund_status"] = 1
	op["type"] = "pdd.order.number.list.increment.get"

	t.Log(SortByDic(op, "&"))
	t.Log(SortByDic(op))
}