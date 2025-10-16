package security

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

type SecurityService interface {
	GetStoreIdFromCtx(ctx *gin.Context) (uint, error)
}

type securityService struct{}

func NewSecurityService() SecurityService {
	return &securityService{}
}

func (s *securityService) GetStoreIdFromCtx(ctx *gin.Context) (uint, error) {
	storeIdUint, exists := ctx.Get("storeId")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Token invalid"})
		return 0, fmt.Errorf("storeId not found in context")
	}

	storeId, ok := storeIdUint.(uint)
	if !ok {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid storeId type"})
		return 0, fmt.Errorf("invalid storeId type")
	}

	return storeId, nil
}
