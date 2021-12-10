package main

import (
	"fmt"

	"github.com/Crosse/godivert"
)

func main() {
	winDivert, err := godivert.OpenHandleWithFilter("true")
	if err != nil {
		panic(err)
	}
	defer winDivert.Close()

	packet, err := winDivert.Recv()
	if err != nil {
		panic(err)
	}

	fmt.Println(packet)

	packet.Send(winDivert)
}
