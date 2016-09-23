package controllers

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/wutongtree/notarization/client/models"
)

// VerifyController main controller
type VerifyController struct {
	baseController
}

// Get default url
func (c *VerifyController) Get() {
	c.Data["Website"] = Website
	c.Data["Email"] = Email
	c.Data["IsSigned"] = false
	c.TplName = "verify.tpl"

	fmt.Printf("---- Get --- \n")
	fmt.Printf("get session uname=%v\n", c.GetSession("uname"))
	fmt.Printf("get session token=%v\n", c.GetSession("token"))

	if c.GetSession("uname") == nil {
		c.Redirect("/", 302)
	}

	c.Data["Username"] = c.GetSession("uname")
}

// Verify verify a signature
func (c *VerifyController) Verify() {
	c.Data["Website"] = Website
	c.Data["Email"] = Email
	c.TplName = "verify.tpl"

	fmt.Printf("---- login --- \n")
	fmt.Printf("get session uname=%v\n", c.GetSession("uname"))
	fmt.Printf("get session token=%v\n", c.GetSession("token"))

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

	// Get form value.
	hash := c.GetString("filehash")
	filesignature := c.GetString("filesignature")

	// Check valid.
	if len(hash) == 0 || len(filesignature) == 0 {
		fmt.Println("need hash and filesignature err")
		return
	}

	f, h, err := c.GetFile("fileup")
	defer f.Close()
	if err != nil {
		fmt.Println("getfile err ", err)
	} else {
		c.SaveToFile("fileup", "/www/"+h.Filename)
	}

	content, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Println("read file err ", err)
		return
	}
	fileContent := base64.StdEncoding.EncodeToString(content)

	md5sum := md5.Sum(content)
	fileHash := fmt.Sprintf("%02x", md5sum)
	if fileHash != strings.ToLower(hash) {
		fmt.Println("hash not match err ", err)

		return
	}

	verified := models.Verify(uname, token, fileContent, fileHash, filesignature)
	if !verified {
		c.Data["Signstatus"] = "签名验证错误."
	} else {
		c.Data["Signstatus"] = "签名验证正确!"
		c.Data["Success"] = true
	}
	c.Data["IsSigned"] = true
	c.Data["Username"] = uname
	return
}
