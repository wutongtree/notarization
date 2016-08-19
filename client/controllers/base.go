package controllers

import (
	"github.com/astaxie/beego"
	"github.com/beego/i18n"
)

// global const
const (
	Website = "https://wutongtree.com"
	Email   = "hyper@crypto2x.com"
)

// baseController represents base router for all other app routers.
// It implemented some methods for the same implementation;
// thus, it will be embedded into other routers.
type baseController struct {
	beego.Controller // Embed struct that has stub implementation of the interface.
	i18n.Locale      // For i18n usage when process data and render template.
}

// Prepare implemented Prepare() method for baseController.
// It's used for language option check and setting.
func (c *baseController) Prepare() {
	// Reset language option.
	c.Lang = "" // This field is from i18n.Locale.

	// 1. Get language information from 'Accept-Language'.
	al := c.Ctx.Request.Header.Get("Accept-Language")
	if len(al) > 4 {
		al = al[:5] // Only compare first 5 letters.
		if i18n.IsExist(al) {
			c.Lang = al
		}
	}

	// 2. Default language is English.
	if len(c.Lang) == 0 {
		c.Lang = "en-US"
	}

	// Set template level language option.
	c.Data["Lang"] = c.Lang
}
