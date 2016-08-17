package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	core "github.com/hyperledger/fabric/core"
	"github.com/hyperledger/fabric/core/crypto"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/hyperledger/fabric/flogging"
	logging "github.com/op/go-logging"
)

var logger = logging.MustGetLogger("app")

// Constants go here.
const fabric = "hyperledger"
const cmdRoot = "app"

// The main command describes the service and
// defaults to printing the help message.
var mainCmd = &cobra.Command{
	Use: "app",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		appCommand := getAppCommandFromCobraCommand(cmd)
		flogging.LoggingInit(appCommand)

		return core.CacheConfiguration()
	},
	Run: func(cmd *cobra.Command, args []string) {
		if versionFlag {
			VersionPrint()
		} else {
			cmd.HelpFunc()(cmd, args)
		}
	},
}

func main() {
	// For environment variables.
	viper.SetEnvPrefix(cmdRoot)
	viper.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)

	// Define command-line flags that are valid for all peer commands and
	// subcommands.
	mainFlags := mainCmd.PersistentFlags()
	mainFlags.BoolVarP(&versionFlag, "version", "v", false, "Display current version of fabric peer server")

	var alternativeCfgPath = os.Getenv("PEER_CFG_PATH")
	if alternativeCfgPath != "" {
		logger.Info("User defined config file path: %s", alternativeCfgPath)
		viper.AddConfigPath(alternativeCfgPath) // Path to look for the config file in
	} else {
		viper.AddConfigPath("./") // Path to look for the config file in
		// Path to look for the config file in based on GOPATH
		gopath := os.Getenv("GOPATH")
		for _, p := range filepath.SplitList(gopath) {
			clientpath := filepath.Join(p, "src/github.com/wutongtree/notarization/app")
			viper.AddConfigPath(clientpath)
		}
	}

	// Now set the configuration file.
	viper.SetConfigName(cmdRoot) // Name of config file (without extension)

	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error when reading %s config file: %s\n", cmdRoot, err))
	}

	mainCmd.AddCommand(VersionCmd())
	mainCmd.AddCommand(AppCmd())

	runtime.GOMAXPROCS(viper.GetInt("app.gomaxprocs"))

	// Init the crypto layer
	primitives.SetSecurityLevel("SHA3", 256)
	if err := crypto.Init(); err != nil {
		panic(fmt.Errorf("Failed to initialize the crypto layer: %s", err))
	}

	// On failure Cobra prints the usage message and error string, so we only
	// need to exit with a non-0 status
	if mainCmd.Execute() != nil {
		os.Exit(1)
	}
	logger.Info("Exiting.....")
}

// getAppCommandFromCobraCommand retreives the peer command from the cobra command struct.
// i.e. for a command of `peer node start`, this should return "node"
// For the main/root command this will return the root name (i.e. peer)
// For invalid commands (i.e. nil commands) this will return an empty string
func getAppCommandFromCobraCommand(command *cobra.Command) string {
	var commandName string

	if command == nil {
		return commandName
	}

	if peerCommand, ok := findChildOfRootCommand(command); ok {
		commandName = peerCommand.Name()
	} else {
		commandName = command.Name()
	}

	return commandName
}

func findChildOfRootCommand(command *cobra.Command) (*cobra.Command, bool) {
	for command.HasParent() {
		if !command.Parent().HasParent() {
			return command, true
		}

		command = command.Parent()
	}

	return nil, false
}
