package main

import (
	"fmt"
	"os"

	"github.com/astaxie/beego"
	"github.com/beego/i18n"
	_ "github.com/wutongtree/notarization/client/routers"
)

func writeHyperledgerExplorer() {
	hyperledger_explorer := beego.AppConfig.String("hyperledger_explorer")
	filename := "static/explorer/hyperledger.js"
	fout, err := os.Create(filename)
	defer fout.Close()

	if err != nil {
		fmt.Printf("Write hyperledger exploer error: %v\n", err)
	} else {
		content := fmt.Sprintf("const REST_ENDPOINT = \"%v\";", hyperledger_explorer)
		fout.WriteString(content)
		fmt.Printf("Write hyperledger explorer with: %v\n", hyperledger_explorer)
	}
}

func main() {
	// Write hyperledger explorer config
	writeHyperledgerExplorer()

	// Register template functions.
	beego.AddFuncMap("i18n", i18n.Tr)

	// Run
	beego.Run()
}
