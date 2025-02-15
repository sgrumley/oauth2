package main

import (
	"github.com/labstack/echo/v4"
	"github.com/sgrumley/oauth/internal/service/auth"
	"github.com/sgrumley/oauth/internal/store"
)

func main() {
	e := echo.New()

	store := store.New()
	authHandler := auth.NewHandler(store)

	// Routes
	e.GET("/authorize", authHandler.Authorization)
	e.GET("/oauth/token", authHandler.Token)

	e.Logger.Fatal(e.Start(":8080"))
}
