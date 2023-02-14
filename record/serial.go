package record

import (
	"fmt"
	"math"
	"strconv"
	"time"
)

const SerialTimeFormat = "20060102"

// DefaultSerial returns a 10 digit serial based on the current day and the minute of the day
func DefaultSerial() uint32 {
	n := time.Now().UTC()
	// calculate two digit number (0-99) based on the minute of the day, 1440 / 14.4545 = 99,0003
	c := int(math.Floor(((float64(n.Hour() + 1)) * float64(n.Minute()+1)) / 14.5454))
	ser, err := strconv.ParseUint(fmt.Sprintf("%s%02d", n.Format(SerialTimeFormat), c), 10, 32)
	if err != nil {
		return uint32(time.Now().Unix())
	}
	return uint32(ser)
}
