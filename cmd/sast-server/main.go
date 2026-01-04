package main

import (
	"fmt"
	"net/http"
	"sast-demo/pkg/service"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// CORS Middleware
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	api := r.Group("/api")
	{
		api.GET("/analyze", func(c *gin.Context) {
			file := c.Query("file")
			if file == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "file parameter required"})
				return
			}

			result, err := service.Analyze(file)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "logs": result.Logs})
				return
			}

			c.JSON(http.StatusOK, result)
		})

		api.GET("/file", func(c *gin.Context) {
			path := c.Query("path")
			if path == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "path parameter required"})
				return
			}

			content, err := service.ReadFile(path)
			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
				return
			}

			c.String(http.StatusOK, content)
		})
	}

	fmt.Println("🚀 SAST Server running on :8080")
	r.Run(":8080")
}
