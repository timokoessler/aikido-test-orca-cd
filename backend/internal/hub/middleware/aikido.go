package middleware

import (
	"net/http"

	"github.com/AikidoSec/firewall-go/zen"
	"github.com/gin-gonic/gin"
)

func AikidoZen() gin.HandlerFunc {
	return func(c *gin.Context) {
		blockResult := zen.ShouldBlockRequest(c)

		if blockResult != nil {
			if blockResult.Type == "rate-limited" {
				message := "You are rate limited by Zen."
				if blockResult.Trigger == "ip" {
					message += " (Your IP: " + *blockResult.IP + ")"
				}
				c.String(http.StatusTooManyRequests, message)
				c.Abort()
				return
			} else if blockResult.Type == "blocked" {
				c.String(http.StatusForbidden, "You are blocked by Zen.")
				c.Abort()
				return
			}
		}

		c.Next()
	}
}
