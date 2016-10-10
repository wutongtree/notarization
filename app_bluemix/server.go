package main

import (
	"fmt"
	"os"
	"runtime"

	"google.golang.org/grpc"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	core "github.com/hyperledger/fabric/core"
	"github.com/hyperledger/fabric/core/crypto"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/hyperledger/fabric/flogging"
	pb "github.com/hyperledger/fabric/protos"
	logging "github.com/op/go-logging"
)

// retry count for connecting to peers
const retryCount = 3

var (
	// Security
	confidentialityOn    bool
	confidentialityLevel pb.ConfidentialityLevel

	// peer related objects
	peerClientConn *grpc.ClientConn
	serverClient   pb.PeerClient

	// Chaincode
	stopPidFile   string
	versionFlag   bool
	chaincodeName string

	// Logging
	logger = logging.MustGetLogger("notarization.app")
)

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
	// Logging
	var formatter = logging.MustStringFormatter(
		`%{color}[%{module}] %{shortfunc} [%{shortfile}] -> %{level:.4s} %{id:03x}%{color:reset} %{message}`,
	)
	logging.SetFormatter(formatter)

	// Init the crypto layer
	primitives.SetSecurityLevel("SHA3", 256)
	if err := crypto.Init(); err != nil {
		panic(fmt.Errorf("Failed to initialize the crypto layer: %s", err))
	}
	// Enable fabric 'confidentiality'
	confidentiality(viper.GetBool("security.privacy"))

	// Initialize a peer connect to submit
	// transactions to the fabric network.
	// A 'core.yaml' file is assumed to be available in the working directory.
	if err := initPeerClient(); err != nil {
		logger.Debugf("Failed initiliazing PeerClient [%s]", err)
		os.Exit(-1)
	}

	// Deploy the chaincode
	err := deployChaincode("")
	if err != nil {
		logger.Errorf("Deploy chaincode error: %v", err)

		os.Exit(-1)
	}

	// Define command-line flags that are valid for all peer commands and
	// subcommands.
	mainFlags := mainCmd.PersistentFlags()
	mainFlags.BoolVarP(&versionFlag, "version", "v", false, "Display current version of fabric peer server")
	mainCmd.AddCommand(VersionCmd())
	mainCmd.AddCommand(AppCmd())

	runtime.GOMAXPROCS(viper.GetInt("core.gomaxprocs"))

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
