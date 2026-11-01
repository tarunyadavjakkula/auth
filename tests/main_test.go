package tests

import (
	"fmt"
	"os"
	"testing"
	"time"
	_ "time/tzdata" /* embedded so zone lookups work on machines without a zoneinfo database */
)

/*
testZoneEnv names the environment variable that moves the whole test process
into a non-UTC zone, e.g. AUTH_TEST_TZ=Asia/Kolkata. The standard TZ variable
is not used because Go ignores it on Windows.
*/
const testZoneEnv = "AUTH_TEST_TZ"

func TestMain(m *testing.M) {
	/* No goroutines exist yet, so replacing time.Local here is race-free */
	if name := os.Getenv(testZoneEnv); name != "" {
		loc, err := time.LoadLocation(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s=%q: %v\n", testZoneEnv, name, err)
			os.Exit(1)
		}
		time.Local = loc
	}
	os.Exit(m.Run())
}
