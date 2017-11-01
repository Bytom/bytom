package version

const Maj = "0"
const Min = "1"
const Fix = "2"

var (
	// The full version string
	Version   = "0.1.2"
	GitCommit string
)

func init() {
	if GitCommit != "" {
		Version += "-" + GitCommit[:8]
	}
}
