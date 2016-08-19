package routers

import (
	"github.com/astaxie/beego"
	"github.com/wutongtree/notarization/client/controllers"
)

var langTypes []string // Languages that are supported.

func init() {
	beego.Router("/", &controllers.LoginController{})
	beego.Router("/login", &controllers.LoginController{}, "post:Login")
	beego.Router("/logout", &controllers.LoginController{}, "get:Logout")

	beego.Router("/list", &controllers.MainController{}, "get:GetSignatures")
	beego.Router("/sign", &controllers.SignController{}, "get:Get;post:Sign")
	beego.Router("/verify", &controllers.VerifyController{}, "get:Get;post:Verify")
}
