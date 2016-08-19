package main

import (
	"github.com/astaxie/beego"
	"github.com/beego/i18n"
	_ "github.com/wutongtree/notarization/client/routers"
)

func main() {
	// Register template functions.
	beego.AddFuncMap("i18n", i18n.Tr)

	// Run
	beego.Run()
}
