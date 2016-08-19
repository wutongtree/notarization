package controllers

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/wutongtree/notarization/client/models"
)

// SignController main controller
type SignController struct {
	baseController
}

// Get default url
func (c *SignController) Get() {
	c.Data["Website"] = Website
	c.Data["Email"] = Email
	c.Data["IsSigned"] = false
	c.TplName = "sign.tpl"

	fmt.Printf("---- Get --- \n")
	fmt.Printf("get session uname=%v\n", c.GetSession("uname"))
	fmt.Printf("get session token=%v\n", c.GetSession("token"))

	if c.GetSession("uname") == nil {
		c.Redirect("/", 302)
	}

	c.Data["Username"] = c.GetSession("uname")
}

// Sign sign a file
func (c *SignController) Sign() {
	c.Data["Website"] = Website
	c.Data["Email"] = Email
	c.TplName = "sign.tpl"

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

	// Check valid.
	if len(hash) == 0 {
		fmt.Println("need hash err")
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
		fmt.Printf("hash not match err: %v-%v\n", hash, fileHash)

		return
	}

	signature := models.Sign(uname, token, h.Filename, fileContent, fileHash)
	if signature == "" {
		c.Data["Signstatus"] = "签名失败."
	} else {
		c.Data["Signstatus"] = "签名成功."
		c.Data["FileName"] = h.Filename
		c.Data["FileHash"] = fileHash
		c.Data["FileSignature"] = signature
	}

	c.Data["IsSigned"] = true
	c.Data["Username"] = uname
	return
}
