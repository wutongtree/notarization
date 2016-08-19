package controllers

import (
	"fmt"

	"github.com/wutongtree/notarization/client/models"
)

// LoginController main controller
type LoginController struct {
	baseController
}

// Get default url
func (c *LoginController) Get() {
	c.Data["Website"] = Website
	c.Data["Email"] = Email
	c.TplName = "login.tpl"

	fmt.Printf("---- Get --- \n")
	fmt.Printf("get session uname=%v\n", c.GetSession("uname"))
	fmt.Printf("get session token=%v\n", c.GetSession("token"))

	if c.GetSession("uname") != nil {
		c.Redirect("/list", 302)
	}
}

// Login to system
func (c *LoginController) Login() {
	c.Data["Website"] = Website
	c.Data["Email"] = Email
	c.TplName = "login.tpl"

	fmt.Printf("---- login --- \n")
	fmt.Printf("get session uname=%v\n", c.GetSession("uname"))
	fmt.Printf("get session token=%v\n", c.GetSession("token"))

	if c.GetSession("uname") != nil {
		c.Redirect("/list", 302)
	}

	// Get form value.
	uname := c.GetString("uname")
	upass := c.GetString("upass")

	// Check valid.
	if len(uname) == 0 || len(upass) == 0 {
		c.Redirect("/", 302)
		return
	}

	logined := models.Login(uname, upass)
	if !logined {
		c.Redirect("/", 302)
		return
	}

	c.SetSession("uname", uname)
	c.SetSession("token", uname)

	fmt.Printf("set session uname=%v\n", c.GetSession("uname"))
	fmt.Printf("set session token=%v\n", c.GetSession("token"))

	c.Data["Username"] = uname
	c.Redirect("/list", 302)

	return
}

// Logout to system
func (c *LoginController) Logout() {
	c.Data["Website"] = Website
	c.Data["Email"] = Email
	c.TplName = "login.tpl"

	if c.GetSession("uname") != nil {
		c.Redirect("/list", 302)
	}

	c.DelSession("uname")
	c.DelSession("upass")

	c.Data["Username"] = ""
	c.Redirect("/", 302)
	return
}
