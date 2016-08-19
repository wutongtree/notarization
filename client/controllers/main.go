package controllers

import (
	"fmt"

	"github.com/wutongtree/notarization/client/models"
)

// MainController main controller
type MainController struct {
	baseController
}

// Get default url
func (c *MainController) Get() {
	c.Data["Website"] = Website
	c.Data["Email"] = Email
	c.TplName = "main.tpl"
}

// GetSignatures get signatures
func (c *MainController) GetSignatures() {
	c.Data["Website"] = Website
	c.Data["Email"] = Email
	c.TplName = "main.tpl"

	fmt.Printf("get session uname=%v\n", c.GetSession("uname"))
	fmt.Printf("get session token=%v\n", c.GetSession("token"))

	// Get form value.
	uname := ""
	token := ""
	if vuname := c.GetSession("uname"); vuname != nil {
		uname = vuname.(string)
	}
	if vtoken := c.GetSession("token"); vtoken != nil {
		token = vtoken.(string)
	}

	// Check valid.
	if len(uname) == 0 || len(token) == 0 {
		c.Redirect("/", 302)
		return
	}

	signatures := models.GetSignatures(uname, token)
	if signatures == nil {
		c.Redirect("/", 302)
		return
	}

	c.Data["Username"] = uname
	c.Data["Signatures"] = *signatures
}
