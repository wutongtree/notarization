package controllers

import (
	"fmt"

	"github.com/astaxie/beego"
	"github.com/astaxie/beego/utils/pagination"

	"github.com/wutongtree/notarization/client/models"
)

// const
const itemsPerPage = 5

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
	c.Data["Username"] = uname

	// page
	page, err := c.GetInt("p")
	if err != nil {
		fmt.Printf("page: %d\n", page)
		page = 1
	}

	pageoffset, err := beego.AppConfig.Int("pageoffset")
	if err != nil {
		pageoffset = itemsPerPage
	}

	signatures := models.GetSignatures(uname, token)
	var result models.SignatureResponse
	countall := 0

	if signatures != nil {
		result.OK = signatures.OK
		result.Error = signatures.Error

		countall = len(signatures.Signatures)

		if page*pageoffset < countall {
			result.Signatures = signatures.Signatures[(page-1)*pageoffset : page*pageoffset]
		} else {
			result.Signatures = signatures.Signatures[(page-1)*pageoffset-1 : countall-1]
		}
		c.Data["Signatures"] = *signatures
	}
	c.Data["Signatures"] = result

	paginator := pagination.SetPaginator(c.Ctx, pageoffset, int64(countall))
	c.Data["paginator"] = paginator
}
