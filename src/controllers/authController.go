package controllers

import (
	"ambassador/src/database"
	"ambassador/src/middlewares"
	"ambassador/src/models"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

type RegisterParam struct {
	FirstName       string `json:"first_name" xml:"first_name" form:"first_name"`
	LastName        string `json:"last_name" xml:"last_name" form:"last_name"`
	Email           string
	Password        string
	PasswordConfirm string `json:"password_confirm" xml:"password_confirm" form:"password_confirm"`
	IsAmbassador    string `json:"is_ambassador" xml:"is_ambassador" form:"is_ambassador"`
}

func Register(c *fiber.Ctx) error {
	data := new(RegisterParam)

	if err := c.BodyParser(data); err != nil {
		return err
	}

	/*
		println(data.FirstName)
		println(data.LastName)
		println(data.Email)
		println(data.Password)
		println(data.PasswordConfirm)
		println(data.IsAmbassador)
	*/

	if data.Password != data.PasswordConfirm {
		c.Status(400)
		return c.JSON(fiber.Map{
			"message": "password do not match",
		})
	}

	user := models.User{
		FirstName:    data.FirstName,
		LastName:     data.LastName,
		Email:        data.Email,
		IsAmbassador: strings.Contains(c.Path(), "/api/ambassador"),
	}
	user.SetPassword(data.Password)

	database.DB.Create(&user)

	return c.JSON(user)
}

func Login(c *fiber.Ctx) error {
	data := new(RegisterParam)

	if err := c.BodyParser(data); err != nil {
		return err
	}

	var user models.User

	database.DB.Where("email = ?", data.Email).First(&user)

	if user.Id == 0 {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"message": "Invalid credentials",
		})
	}

	if err := user.ComparePassword(data.Password); err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"message": "Invalid credentials",
		})
	}

	isAmbassador := strings.Contains(c.Path(), "/api/ambassador")

	var scope string

	if isAmbassador {
		scope = "ambassador"
	} else {
		scope = "admin"
	}

	if !isAmbassador && user.IsAmbassador {
		c.Status(fiber.StatusUnauthorized)
		return c.JSON(fiber.Map{
			"message": "unauthorized",
		})
	}

	println(scope)

	token, err := middlewares.GenerateJWT(user.Id, scope)

	if err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"message": "Invalid credentials",
		})
	}

	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    token,
		Expires:  time.Now().Add(time.Hour * 24),
		HTTPOnly: true,
		//Secure: true,
	}

	c.Cookie(&cookie)

	return c.JSON(fiber.Map{
		"mmesage": "success",
	})
}

func User(c *fiber.Ctx) error {
	id, _ := middlewares.GetUserId(c)

	var user models.User

	database.DB.Where("id = ?", id).First(&user)

	if strings.Contains(c.Path(), "/api/ambassador") {
		ambassador := models.Ambassador(user)
		ambassador.CalculateRevenue(database.DB)
		return c.JSON(ambassador)
	}

	return c.JSON(user)
}

func Logout(c *fiber.Ctx) error {
	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
	}

	c.Cookie(&cookie)

	return c.JSON(fiber.Map{
		"mmesage": "success",
	})
}

func UpdateInfo(c *fiber.Ctx) error {
	data := new(RegisterParam)

	if err := c.BodyParser(data); err != nil {
		return err
	}

	id, _ := middlewares.GetUserId(c)

	user := models.User{
		Id: id,
	}

	user.SetPassword(data.Password)

	database.DB.Model(&user).Updates(&user)

	return c.JSON(user)
}

func UpdatePassword(c *fiber.Ctx) error {
	data := new(RegisterParam)

	if err := c.BodyParser(data); err != nil {
		return err
	}

	if data.Password != data.PasswordConfirm {
		c.Status(400)
		return c.JSON(fiber.Map{
			"message": "password do not match",
		})
	}

	id, _ := middlewares.GetUserId(c)

	user := models.User{
		Id: id,
	}

	user.SetPassword(data.Password)

	database.DB.Model(&user).Updates(&user)

	return c.JSON(user)
}
