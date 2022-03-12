// Package unix_time is used to use unix timestamps in the external API, while the internal Go code can still use time.Time
package unix_time

import (
	"strconv"
	"time"
)

type Time time.Time

func (t Time) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(time.Time(t).Unix(), 10)), nil
}

func (t *Time) UnmarshalJSON(s []byte) (err error) {
	r := string(s)
	q, err := strconv.ParseInt(r, 10, 64)
	if err != nil {
		return err
	}
	*(*time.Time)(t) = time.Unix(q, 0)
	return nil
}

func (t Time) Time() time.Time {
	return time.Time(t).UTC()
}

func (t Time) GobEncode() ([]byte, error) {
	return t.Time().GobEncode()
}

func (t *Time) GobDecode(data []byte) error {
	var t2 time.Time
	if err := t2.GobDecode(data); err != nil {
		return err
	}
	*t = Time(t2)
	return nil
}
